package net.mullvad.mullvadvpn.feature.vpnsettings.impl.extrapeers

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.tooling.preview.Preview
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.compose.dropUnlessResumed
import net.mullvad.mullvadvpn.common.compose.CollectSideEffectWithLifecycle
import net.mullvad.mullvadvpn.common.compose.showSnackbarImmediately
import net.mullvad.mullvadvpn.core.Navigator
import net.mullvad.mullvadvpn.lib.ui.component.MullvadSmallTopBar
import net.mullvad.mullvadvpn.lib.ui.component.button.NavigateBackIconButton
import net.mullvad.mullvadvpn.lib.ui.component.listitem.SwitchListItem
import net.mullvad.mullvadvpn.lib.ui.component.textfield.mullvadWhiteTextFieldColors
import net.mullvad.mullvadvpn.lib.ui.designsystem.MullvadSnackbar
import net.mullvad.mullvadvpn.lib.ui.resource.R
import net.mullvad.mullvadvpn.lib.ui.theme.AppTheme
import net.mullvad.mullvadvpn.lib.ui.theme.Dimens
import org.koin.androidx.compose.koinViewModel

@Preview
@Composable
private fun PreviewExtraPeersScreen() {
    AppTheme {
        ExtraPeersScreen(
            state = ExtraPeersUiState(enabled = false, configText = "", dirty = false),
            snackbarHostState = SnackbarHostState(),
            onBackClick = {},
            onToggle = {},
            onConfigChanged = {},
            onSave = {},
        )
    }
}

@Composable
fun ExtraPeers(navigator: Navigator) {
    val viewModel = koinViewModel<ExtraPeersViewModel>()
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val resources = LocalResources.current

    CollectSideEffectWithLifecycle(viewModel.uiSideEffect) {
        when (it) {
            ExtraPeersSideEffect.Saved ->
                snackbarHostState.showSnackbarImmediately(
                    message = resources.getString(R.string.extra_wg_peers_saved_snackbar)
                )
        }
    }

    ExtraPeersScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onBackClick = dropUnlessResumed { navigator.goBack() },
        onToggle = viewModel::onToggle,
        onConfigChanged = viewModel::onConfigChanged,
        onSave = viewModel::onSave,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ExtraPeersScreen(
    state: ExtraPeersUiState,
    snackbarHostState: SnackbarHostState,
    onBackClick: () -> Unit,
    onToggle: (Boolean) -> Unit,
    onConfigChanged: (String) -> Unit,
    onSave: () -> Unit,
) {
    Scaffold(
        topBar = {
            MullvadSmallTopBar(
                title = stringResource(R.string.extra_wg_peers_title),
                navigationIcon = { NavigateBackIconButton(onNavigateBack = onBackClick) },
                actions = {
                    TextButton(
                        enabled = state.dirty,
                        colors =
                            ButtonDefaults.textButtonColors()
                                .copy(contentColor = MaterialTheme.colorScheme.onPrimary),
                        onClick = onSave,
                    ) {
                        Text(text = stringResource(R.string.extra_wg_peers_save))
                    }
                },
            )
        },
        snackbarHost = {
            SnackbarHost(
                snackbarHostState,
                snackbar = { snackbarData -> MullvadSnackbar(snackbarData = snackbarData) },
            )
        },
    ) { paddingValues ->
        Column(modifier = Modifier.padding(paddingValues).fillMaxSize()) {
            SwitchListItem(
                title = stringResource(R.string.extra_wg_peers_title),
                isToggled = state.enabled,
                isEnabled = true,
                onCellClicked = onToggle,
            )
            Spacer(modifier = Modifier.height(Dimens.cellVerticalSpacing))
            TextField(
                modifier = Modifier.weight(1f).fillMaxSize(),
                value = state.configText,
                onValueChange = onConfigChanged,
                placeholder = { Text(text = stringResource(R.string.extra_wg_peers_config_hint)) },
                colors = mullvadWhiteTextFieldColors(),
                textStyle =
                    MaterialTheme.typography.bodyMedium.copy(
                        fontFamily = FontFamily.Monospace,
                        textDirection = TextDirection.Ltr,
                    ),
                maxLines = Int.MAX_VALUE,
            )
        }
    }
}
