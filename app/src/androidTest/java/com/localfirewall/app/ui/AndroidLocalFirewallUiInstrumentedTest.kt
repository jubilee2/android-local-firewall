package com.localfirewall.app.ui

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AndroidLocalFirewallUiInstrumentedTest {
    @get:Rule
    val composeRule = createComposeRule()

    @Test
    fun rendersStatusAndNavigatesAcrossAllTabs() {
        var started by mutableStateOf(false)
        var uiState by mutableStateOf(FirewallUiState())
        var startClicks = 0

        composeRule.setContent {
            AndroidLocalFirewallApp(
                serviceStarted = started,
                uiState = uiState,
                onStartFirewall = {
                    startClicks += 1
                    started = true
                },
                onStopFirewall = { started = false },
                onSelectTab = { selected -> uiState = uiState.copy(selectedTab = selected) },
            )
        }

        composeRule.onNodeWithText("Firewall: OFF").assertIsDisplayed()
        composeRule.onNodeWithText("Start Firewall").performClick()
        assertEquals(1, startClicks)
        composeRule.onNodeWithText("Firewall: STARTED").assertIsDisplayed()

        composeRule.onNodeWithText("Apps").performClick()
        composeRule.onNodeWithText("Show system applications").assertIsDisplayed()

        composeRule.onNodeWithText("Rules").performClick()
        composeRule.onNodeWithText("Add Network Rule").assertIsDisplayed()

        composeRule.onNodeWithText("Logs").performClick()
        composeRule.onNodeWithText("Record local traffic metadata").assertIsDisplayed()
    }
}
