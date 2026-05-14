package net.mullvad.mullvadvpn.feature.vpnsettings.impl.navigation

import androidx.navigation3.runtime.EntryProviderScope
import net.mullvad.mullvadvpn.core.NavKey2
import net.mullvad.mullvadvpn.core.Navigator
import net.mullvad.mullvadvpn.core.animation.slideInHorizontalTransition
import net.mullvad.mullvadvpn.core.scene.ListDetailSceneStrategy
import net.mullvad.mullvadvpn.feature.vpnsettings.api.ExtraPeersNavKey
import net.mullvad.mullvadvpn.feature.vpnsettings.impl.extrapeers.ExtraPeers

internal fun EntryProviderScope<NavKey2>.extraPeersEntry(navigator: Navigator) {
    entry<ExtraPeersNavKey>(
        metadata = ListDetailSceneStrategy.listPane() + slideInHorizontalTransition()
    ) {
        ExtraPeers(navigator = navigator)
    }
}
