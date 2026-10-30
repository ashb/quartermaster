const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const { buildSchema, parse, print, visit } =
    require(path.resolve(process.env.QM_REFERENCE_GRAPHQL));

const maps = new Set(['properties', 'schemas', 'responses', 'headers', 'content', 'encoding', 'links', 'callbacks', 'securitySchemes', 'mapping']);
const documentation = new Set(['description', 'summary', 'externalDocs', 'example', 'examples']);

function canonical(value, mode = 'schema') {
    if (Array.isArray(value)) return value.map(item => canonical(item, mode));
    if (value === null || typeof value !== 'object') return value;
    return Object.fromEntries(Object.keys(value).sort().filter(key =>
        mode !== 'schema' || !documentation.has(key)).map(key => {
        const childMode = mode === 'data' || (mode === 'schema' && ['default', 'enum', 'const'].includes(key))
            ? 'data' : mode === 'schema' && maps.has(key) ? 'map' : 'schema';
        return [key, canonical(value[key], childMode)];
    }));
}

function restInventory(source) {
    const schema = JSON.parse(source);
    assert.match(schema.openapi, /^3\./);
    const inventory = new Map();
    const methods = new Set(['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace']);
    for (const [route, item] of Object.entries(schema.paths)) {
        assert.ok(route.startsWith('/'), `Invalid REST path: ${route}`);
        for (const [method, operation] of Object.entries(item)) {
            if (!methods.has(method)) continue;
            assert.ok(typeof operation.operationId === 'string' && operation.operationId.length > 0,
                `Missing operationId: ${method} ${route}`);
            inventory.set(`${method.toUpperCase()} ${route}`, JSON.stringify(canonical({
                operation,
                parameters: item.parameters ?? [],
                servers: item.servers ?? schema.servers ?? [],
                security: operation.security ?? schema.security ?? [],
            })));
        }
    }
    assert.ok(inventory.size > 0, 'No REST operations in schema');
    for (const [kind, components] of Object.entries(schema.components ?? {})) {
        for (const [name, component] of Object.entries(components)) {
            inventory.set(`component ${kind}.${name}`, JSON.stringify(canonical(component)));
        }
    }
    return inventory;
}

function graphqlInventory(source) {
    const schema = buildSchema(source);
    assert.ok(schema.getQueryType(), 'No GraphQL query type in schema');
    const document = visit(parse(source), {
        enter(node) {
            if (node.kind === 'Directive' && node.name.value === 'docsCategory') return null;
            const result = { ...node, description: undefined };
            if (node.kind === 'StringValue') result.block = false;
            const name = item => item.name?.value ?? (item.kind === 'Name' ? item.value : item.operation);
            for (const key of ['fields', 'arguments', 'values', 'interfaces', 'types', 'locations', 'operationTypes']) {
                if (Array.isArray(node[key]) && node[key].every(item => typeof name(item) === 'string')) {
                    result[key] = [...node[key]].sort((a, b) => name(a) < name(b) ? -1 : name(a) > name(b) ? 1 : 0);
                }
            }
            return result;
        },
    });
    const inventory = new Map();
    const headers = new Map();
    for (const definition of document.definitions) {
        const name = definition.kind === 'DirectiveDefinition'
            ? `@${definition.name.value}` : definition.name?.value ?? 'schema';
        if (!headers.has(name)) headers.set(name, []);
        headers.get(name).push(print({ ...definition, fields: undefined, values: undefined }));
        for (const field of definition.fields ?? definition.values ?? []) {
            inventory.set(`${name}.${field.name.value}`, print(field));
        }
    }
    for (const [name, parts] of headers) inventory.set(name, parts.sort().join('\n'));
    return inventory;
}

function changes(before, after) {
    const differences = [];
    for (const key of [...new Set([...before.keys(), ...after.keys()])].sort()) {
        if (!before.has(key)) differences.push(`Added ${key}`);
        else if (!after.has(key)) differences.push(`Removed ${key}`);
        else if (before.get(key) !== after.get(key)) differences.push(`Changed ${key}`);
    }
    return differences;
}

async function download(url, fetchSchema = fetch) {
    const response = await fetchSchema(url, {
        signal: AbortSignal.timeout(30_000),
        cache: 'no-store',
        headers: { 'Cache-Control': 'no-cache' },
    });
    assert.ok(response.ok, `${url}: HTTP ${response.status}`);
    return response.text();
}

module.exports = { restInventory, graphqlInventory, changes, download };

function fingerprints(rest, graphql) {
    return new Map([
        ...[...restInventory(rest)].map(([key, signature]) => [`REST ${key}`, signature]),
        ...[...graphqlInventory(graphql)].map(([key, signature]) => [`GraphQL ${key}`, signature]),
    ].map(([key, signature]) => [key, createHash('sha256').update(signature).digest().subarray(0, 8).toString('base64url')]));
}

async function main() {
    const args = process.argv.slice(2);
    assert.ok(args.length === 0 || (args.length === 1 && args[0] === '--live'), 'expected --live or no arguments');
    const baseline = fingerprints(
        readFileSync(process.env.QM_GITHUB_REST_SCHEMA, 'utf8'),
        readFileSync(process.env.QM_GITHUB_GRAPHQL_SCHEMA, 'utf8'),
    );
    const current = args.length ? fingerprints(...await Promise.all([
        download('https://raw.githubusercontent.com/github/rest-api-description/main/descriptions/api.github.com/api.github.com.json'),
        download('https://raw.githubusercontent.com/github/docs/main/src/graphql/data/fpt/schema.docs.graphql'),
    ])) : baseline;
    process.stdout.write(JSON.stringify({ entries: Object.fromEntries(current), changes: changes(baseline, current) }));
}

if (require.main === module) {
    main().catch(error => { console.error(error); process.exitCode = 1; });
}
