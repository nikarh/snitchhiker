package dev.nikarh.snitchhiker.core

import org.junit.Assert.assertEquals
import org.junit.Test
import snitchhiker.v1.AlertsChanged
import snitchhiker.v1.Notice
import snitchhiker.v1.Prompt
import snitchhiker.v1.PromptResolved
import snitchhiker.v1.Proposal
import snitchhiker.v1.ProposalState

class NodeStateTest {
    @Test
    fun promptsOpenAndResolve() {
        val opened = NodeState().apply(Notice(prompt = Prompt(id = 3, exe = "/usr/bin/curl")))
        assertEquals(setOf(3L), opened.prompts.keys)
        assertEquals(emptySet<Long>(), opened.apply(Notice(prompt_resolved = PromptResolved(id = 3))).prompts.keys)
    }

    @Test
    fun proposalsAndAlertsAreCounted() {
        val state =
            NodeState()
                .apply(Notice(proposal = Proposal(id = 1, state = ProposalState.PROPOSAL_STATE_PENDING)))
                .apply(Notice(proposal = Proposal(id = 2, state = ProposalState.PROPOSAL_STATE_APPROVED)))
                .apply(Notice(alerts_changed = AlertsChanged(open_ = 4)))
        assertEquals(1, state.pendingProposals)
        assertEquals(4, state.openAlerts)
    }
}
