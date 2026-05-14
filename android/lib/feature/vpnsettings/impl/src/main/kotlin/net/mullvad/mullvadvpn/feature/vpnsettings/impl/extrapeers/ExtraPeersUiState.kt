package net.mullvad.mullvadvpn.feature.vpnsettings.impl.extrapeers

data class ExtraPeersUiState(
    val enabled: Boolean,
    val configText: String,
    val dirty: Boolean,
)
