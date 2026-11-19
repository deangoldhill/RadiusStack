'use strict';
// Existing receiver policy extracted for a deterministic regression test.
function reverseReplayAllowed(status) {
  // Partial is terminal: preserved/conflicting rows require operator review,
  // but the job is no longer running and must not stop ongoing reverse replay.
  // A pre-drain failure occurs before the peer has ever been prepared.
  return ['idle', 'finalized', 'completed', 'partial', 'failed-pre-drain'].includes(status);
}
module.exports = {reverseReplayAllowed};
