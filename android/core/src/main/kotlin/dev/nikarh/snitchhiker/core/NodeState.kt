package dev.nikarh.snitchhiker.core

import snitchhiker.v1.Approval
import snitchhiker.v1.Notice
import snitchhiker.v1.Prompt
import snitchhiker.v1.Proposal
import snitchhiker.v1.ProposalState
import snitchhiker.v1.Status

/** What the app knows of a node from its notices and the requests it made. */
data class NodeState(
    val connected: Boolean = false,
    /** Why it isn't connected, when it isn't. */
    val error: String? = null,
    val status: Status? = null,
    val prompts: Map<Long, Prompt> = emptyMap(),
    val approvals: Map<Long, Approval> = emptyMap(),
    val proposals: Map<Long, Proposal> = emptyMap(),
    val openAlerts: Int = 0,
    /** Bumped when the node's rules changed: views list them again. */
    val rulesVersion: Int = 0,
) {
    val pendingProposals: Int get() = proposals.values.count { it.state == ProposalState.PROPOSAL_STATE_PENDING }

    /** The state after [notice]. */
    fun apply(notice: Notice): NodeState =
        when {
            notice.prompt != null -> copy(prompts = prompts + (notice.prompt.id to notice.prompt))
            notice.prompt_resolved != null -> copy(prompts = prompts - notice.prompt_resolved.id)
            notice.approval != null -> copy(approvals = approvals + (notice.approval.id to notice.approval))
            notice.approval_resolved != null -> copy(approvals = approvals - notice.approval_resolved.id)
            notice.proposal != null -> copy(proposals = proposals + (notice.proposal.id to notice.proposal))
            notice.alert != null -> copy(openAlerts = openAlerts + if (notice.alert.acknowledged) 0 else 1)
            notice.alerts_changed != null -> copy(openAlerts = notice.alerts_changed.open_)
            notice.rules_changed != null -> copy(rulesVersion = rulesVersion + 1)
            else -> this
        }
}
