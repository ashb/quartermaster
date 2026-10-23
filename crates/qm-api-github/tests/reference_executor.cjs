const fs = require('node:fs');
const path = require('node:path');
const { buildSchema, graphqlSync, responsePathAsArray } = require(
  path.resolve(process.env.QM_REFERENCE_GRAPHQL),
);

const schema = buildSchema(`
  type Query { repository(owner: String!, name: String!): Repository! }
  type Mutation {
    closeIssue(input: IssueInput!): CloseIssuePayload!
    deleteIssue(input: IssueInput!): DeleteIssuePayload!
  }
  input IssueInput { issueId: ID!, clientMutationId: String }
  enum IssueState { OPEN, CLOSED }
  type Repository {
    name: String!
    issue(number: Int!): Issue!
    issues(first: Int, last: Int, after: String, before: String, states: [IssueState!]): IssueConnection!
    future: String!
  }
  type Issue { number: Int!, title: String!, repository: Repository! }
  type IssueConnection {
    nodes: [Issue!]!
    edges: [IssueEdge!]!
    pageInfo: PageInfo!
    totalCount: Int!
  }
  type IssueEdge { node: Issue!, cursor: String! }
  type PageInfo { hasNextPage: Boolean!, endCursor: String }
  type CloseIssuePayload { clientMutationId: String, issue: Issue! }
  type DeleteIssuePayload { clientMutationId: String }
`);

function execute(request) {
  const observation = { effects: [], resources: [], roots: [], unfamiliar: false };
  const paths = new Map();
  const result = graphqlSync({
    schema,
    source: request.query,
    variableValues: request.variables,
    operationName: request.operationName,
    rootValue: {},
    fieldResolver(source, args, context, info) {
      const responsePath = responsePathAsArray(info.path).filter(key => typeof key === 'string');
      const parent = responsePath.slice(0, -1).join('\0');
      const semanticPath = [...(paths.get(parent) || []), info.fieldName];
      paths.set(responsePath.join('\0'), semanticPath);
      const field = `${info.parentType.name}.${info.fieldName}`;
      const effect = {
        'Query.repository': 'ReadRepository',
        'Repository.issue': 'ReadIssue',
        'Repository.issues': 'ListIssues',
        'Mutation.closeIssue': 'CloseIssue',
        'Mutation.deleteIssue': 'DeleteIssue',
      }[field];
      if (effect) observation.effects.push({ kind: effect, path: semanticPath });
      if (info.parentType.name === 'Query' || info.parentType.name === 'Mutation') {
        observation.roots.push([info.parentType.name, info.fieldName]);
      }
      switch (field) {
        case 'Query.repository':
          observation.resources.push(`repository:${args.owner}/${args.name}`);
          return { owner: args.owner, name: args.name };
        case 'Repository.issue':
          observation.resources.push(`issue:${args.number}`);
          return { repository: source, number: args.number };
        case 'Repository.issues':
          return { repository: source };
        case 'Repository.future':
          observation.unfamiliar = true;
          return 'future';
        case 'Issue.repository':
          return source.repository;
        case 'Issue.title':
          return 'fixture';
        case 'IssueConnection.nodes':
          return [{ repository: source.repository, number: 1 }];
        case 'IssueConnection.edges':
          return [{ repository: source.repository }];
        case 'IssueConnection.pageInfo':
          return {};
        case 'IssueConnection.totalCount':
          return 1;
        case 'IssueEdge.node':
          return { repository: source.repository, number: 1 };
        case 'IssueEdge.cursor':
        case 'PageInfo.endCursor':
          return 'cursor';
        case 'PageInfo.hasNextPage':
          return false;
        case 'Mutation.closeIssue':
        case 'Mutation.deleteIssue':
          observation.resources.push(`node:${args.input.issueId}`);
          return { clientMutationId: args.input.clientMutationId || null };
        case 'CloseIssuePayload.issue':
          return { repository: { owner: 'scope', name: 'repository' }, number: 42 };
        default:
          return source[info.fieldName];
      }
    },
  });
  return { ...observation, errors: (result.errors || []).map(error => error.message) };
}

const requests = JSON.parse(fs.readFileSync(0, 'utf8'));
process.stdout.write(JSON.stringify(requests.map(execute)));
