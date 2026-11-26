import {
  DmarcStoreDO,
  handleWorkerEmail,
  handleWorkerFetch,
  handleWorkerScheduled,
  type Env
} from './worker-app.js';
import { readBoundedEmailStream } from './email-handler.js';

export { DmarcStoreDO };

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    return handleWorkerFetch(request, env);
  },
  async email(message: ForwardableEmailMessage, env: Env): Promise<void> {
    let rawText: string;
    try {
      rawText = await readBoundedEmailStream(message.raw, message.rawSize);
    } catch (err: unknown) {
      message.setReject(err instanceof Error ? err.message : 'Incoming email exceeds maximum allowed size');
      return;
    }
    const res = await handleWorkerEmail(rawText, env);
    if (!res.accepted && res.rejectedReason?.toLowerCase().includes('ruf')) {
      message.setReject('DMARCZero rejects RUF forensic reports to protect email privacy');
    }
  },
  async scheduled(_controller: ScheduledController, env: Env): Promise<void> {
    await handleWorkerScheduled(env);
  }
};
