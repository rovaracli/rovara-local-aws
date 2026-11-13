export const hello = async (event, context) => {
  console.log("hello from node", event.name);
  return { hello: event.name, pid: process.pid, request_id: context.awsRequestId, arn: context.invokedFunctionArn };
};
export const echo = async (event) => event;
export const error = async () => { throw new TypeError("kaboom from node"); };
export const sleepy = async () => { await new Promise(r => setTimeout(r, 30000)); return "late"; };
export const big = async (event) => "x".repeat(event.n);
