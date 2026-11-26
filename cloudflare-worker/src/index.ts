import {
  DmarcStoreDO,
  handleWorkerEmail,
  handleWorkerFetch,
  handleWorkerScheduled,
  type Env
} from './worker-app.js';

export { DmarcStoreDO };

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    return handleWorkerFetch(request, env);
  },
  async email(message: ForwardableEmailMessage, env: Env): Promise<void> {
    const rawText = await new Response(message.raw).text();
    const res = await handleWorkerEmail(rawText, env);
    if (!res.accepted && res.rejectedReason?.toLowerCase().includes('ruf')) {
      message.setReject('DMARCZero rejects RUF forensic reports to protect email privacy');
    }
  },
  async scheduled(_controller: ScheduledController, env: Env): Promise<void> {
    await handleWorkerScheduled(env);
  }
};
