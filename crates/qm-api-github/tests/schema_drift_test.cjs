const assert = require('node:assert/strict');
const { test } = require('node:test');
const { restInventory, graphqlInventory, changes, download } = require('./schema_drift.cjs');

function rest(paths) {
    return JSON.stringify({ openapi: '3.0.3', paths });
}

test('new REST paths and methods require review', () => {
    const before = restInventory(rest({ '/issues': { get: { operationId: 'issues/list' } } }));
    const after = restInventory(rest({
        '/issues': { get: { operationId: 'issues/list' }, post: { operationId: 'issues/create' } },
        '/new': { get: { operationId: 'new/list' } },
    }));
    assert.deepEqual(changes(before, after), ['Added GET /new', 'Added POST /issues']);
    assert.deepEqual(changes(after, before), ['Removed GET /new', 'Removed POST /issues']);
});

test('REST operation identity changes require review', () => {
    assert.deepEqual(changes(
        restInventory(rest({ '/issues': { get: { operationId: 'issues/list' } } })),
        restInventory(rest({ '/issues': { get: { operationId: 'issues/replaced' } } })),
    ), ['Changed GET /issues']);
});

test('REST documentation and path metadata do not add endpoints', () => {
    assert.deepEqual(changes(
        restInventory(rest({ '/issues': { get: { operationId: 'issues/list' } } })),
        restInventory(rest({ '/issues': {
            description: 'New documentation', parameters: [],
            get: { operationId: 'issues/list', description: 'Updated', summary: 'List' },
        } })),
    ), []);
});

test('REST parameters and shared component changes require review', () => {
    const before = {
        openapi: '3.0.3',
        paths: { '/issues': { get: {
            operationId: 'issues/list',
            parameters: [{ name: 'page', in: 'query', schema: { type: 'integer' } }],
        } } },
        components: { schemas: { Issue: { properties: { description: { type: 'string' } } } } },
    };
    const after = structuredClone(before);
    after.paths['/issues'].get.parameters[0].required = true;
    after.components.schemas.Issue.properties.description.type = 'integer';
    assert.deepEqual(changes(restInventory(JSON.stringify(before)), restInventory(JSON.stringify(after))), [
        'Changed GET /issues', 'Changed component schemas.Issue',
    ]);
});

test('REST documentation is ignored without discarding API data named description', () => {
    const before = {
        openapi: '3.0.3',
        paths: { '/issues': { get: { operationId: 'issues/list' } } },
        components: { schemas: { Issue: {
            description: 'Docs',
            properties: { description: { type: 'string', default: 'old' } },
        } } },
    };
    const after = structuredClone(before);
    after.components.schemas.Issue.description = 'New docs';
    assert.deepEqual(changes(restInventory(JSON.stringify(before)), restInventory(JSON.stringify(after))), []);
    after.components.schemas.Issue.properties.description.default = 'new';
    assert.deepEqual(changes(restInventory(JSON.stringify(before)), restInventory(JSON.stringify(after))), [
        'Changed component schemas.Issue',
    ]);
});

test('REST discriminator mapping values named description remain significant', () => {
    const before = {
        openapi: '3.0.3',
        paths: { '/issues': { get: { operationId: 'issues/list' } } },
        components: { schemas: { Issue: { discriminator: {
            propertyName: 'kind', mapping: { description: '#/components/schemas/Old' },
        } } } },
    };
    const after = structuredClone(before);
    after.components.schemas.Issue.discriminator.mapping.description = '#/components/schemas/New';
    assert.deepEqual(changes(restInventory(JSON.stringify(before)), restInventory(JSON.stringify(after))), [
        'Changed component schemas.Issue',
    ]);
});

test('new GraphQL fields, inputs, enum values and mutations require review', () => {
    const before = graphqlInventory(`
        type Query { issue: String }
        type Mutation { close(input: Change!): Boolean }
        input Change { id: ID! }
        enum State { CLOSED }
    `);
    const after = graphqlInventory(`
        type Query { issue: String, description: String }
        type Mutation { close(input: Change!): Boolean, reopen(input: Change!): Boolean }
        input Change { id: ID!, reason: State }
        enum State { CLOSED OPEN }
        type Added { id: ID! }
    `);
    assert.deepEqual(changes(before, after), [
        'Added Added', 'Added Added.id', 'Added Change.reason',
        'Added Mutation.reopen', 'Added Query.description', 'Added State.OPEN',
    ]);
});

test('GraphQL argument, default and return type changes require review', () => {
    const before = graphqlInventory('type Query { issue(number: Int = 1): String }');
    for (const field of [
        'issue(number: Int = 2): String',
        'issue(number: Int = 1, owner: String): String',
        'issue(number: Int!): String',
        'issue(number: Int = 1): [String]',
    ]) {
        assert.deepEqual(changes(before, graphqlInventory(`type Query { ${field} }`)), [
            'Changed Query.issue',
        ]);
    }
});

test('GraphQL unions and interface membership require review', () => {
    const common = 'interface Node { id: ID! } type Issue implements Node { id: ID! }';
    const before = graphqlInventory(`${common} type Query { result: Result } union Result = Issue`);
    const after = graphqlInventory(`${common} type Query { result: Result } union Result = Issue | Query`);
    assert.deepEqual(changes(before, after), ['Changed Result']);
    assert.deepEqual(changes(before, graphqlInventory(
        'interface Node { id: ID! } type Issue { id: ID! } type Query { result: Result } union Result = Issue',
    )), ['Changed Issue']);
});

test('GraphQL documentation and ordering do not cause drift', () => {
    assert.deepEqual(changes(
        graphqlInventory('type Query { b(z: Int, a: Int): String, description: String }'),
        graphqlInventory(`"Docs" type Query {
            "A field literally named description" description: String
            "More docs" b("Arg docs" a: Int, z: Int): String
        }`),
    ), []);
});

test('GraphQL extensions retain base union and interface membership', () => {
    const types = 'type A { id: ID } type B { id: ID } type C { id: ID } type Query { result: Result }';
    assert.deepEqual(changes(
        graphqlInventory(`${types} union Result = A extend union Result = B`),
        graphqlInventory(`${types} union Result = C extend union Result = B`),
    ), ['Changed Result']);
    const common = 'interface Node { id: ID } type Query { issue: Issue }';
    assert.deepEqual(changes(
        graphqlInventory(`${common} type Issue implements Node { id: ID } extend type Issue { name: String }`),
        graphqlInventory(`${common} type Issue { id: ID } extend type Issue { name: String }`),
    ), ['Changed Issue']);
});

test('applied GraphQL directives retain accepted ID types and preview gates', () => {
    const definitions = `
        directive @possibleTypes(concreteTypes: [String!]) on INPUT_FIELD_DEFINITION
        directive @preview(toggledBy: String!) on FIELD_DEFINITION
        type Query { issue: String @preview(toggledBy: "old") }
    `;
    const before = `${definitions} input Change { ownerId: ID! @possibleTypes(concreteTypes: ["Organization"]) }`;
    const after = `${definitions.replace('toggledBy: "old"', 'toggledBy: "new"')}
        input Change { ownerId: ID! @possibleTypes(concreteTypes: ["Repository"]) }
    `;
    assert.deepEqual(changes(graphqlInventory(before), graphqlInventory(after)), [
        'Changed Change.ownerId', 'Changed Query.issue',
    ]);
});

test('missing or malformed schemas fail instead of appearing unchanged', () => {
    for (const source of ['invalid', '{}', rest({}), rest({ '/issues': { get: {} } })]) {
        assert.throws(() => restInventory(source));
    }
    for (const source of ['', 'type Query {', 'type Query { field: Missing }']) {
        assert.throws(() => graphqlInventory(source));
    }
});

test('download errors fail without reusing a cached schema', async () => {
    await assert.rejects(download('https://example.invalid/schema', async () => {
        throw new Error('offline');
    }), /offline/);
    await assert.rejects(download('https://example.invalid/schema', async () =>
        new Response('unavailable', { status: 503 })), /503/);
});
