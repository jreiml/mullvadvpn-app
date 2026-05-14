package net.mullvad.mullvadvpn.feature.vpnsettings.impl.extrapeers

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import java.io.File
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.WhileSubscribed
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import net.mullvad.mullvadvpn.lib.common.constant.VIEW_MODEL_STOP_TIMEOUT
import net.mullvad.mullvadvpn.lib.repository.UserPreferencesRepository

class ExtraPeersViewModel(
    private val userPreferencesRepository: UserPreferencesRepository,
    private val context: Context,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
) : ViewModel() {

    private val _enabled = MutableStateFlow(false)
    private val _configText = MutableStateFlow("")
    private val _dirty = MutableStateFlow(false)

    val uiState =
        combine(_enabled, _configText, _dirty) { enabled, configText, dirty ->
                ExtraPeersUiState(enabled = enabled, configText = configText, dirty = dirty)
            }
            .stateIn(
                viewModelScope,
                SharingStarted.WhileSubscribed(VIEW_MODEL_STOP_TIMEOUT),
                ExtraPeersUiState(enabled = false, configText = "", dirty = false),
            )

    private val _uiSideEffect = Channel<ExtraPeersSideEffect>()
    val uiSideEffect = _uiSideEffect.receiveAsFlow()

    init {
        viewModelScope.launch(dispatcher) {
            _enabled.value = userPreferencesRepository.extraPeersEnabled().first()
            _configText.value = userPreferencesRepository.extraPeersConfig().first()
        }
    }

    fun onToggle(enabled: Boolean) {
        _enabled.value = enabled
        _dirty.value = true
    }

    fun onConfigChanged(config: String) {
        _configText.value = config
        _dirty.value = true
    }

    fun onSave() {
        viewModelScope.launch(dispatcher) {
            val enabled = _enabled.value
            val config = _configText.value
            userPreferencesRepository.setExtraPeers(enabled, config)
            syncFile(enabled, config)
            _dirty.value = false
            _uiSideEffect.send(ExtraPeersSideEffect.Saved)
        }
    }

    private fun syncFile(enabled: Boolean, config: String) {
        val file = File(context.filesDir, "extra-peers.conf")
        if (enabled && config.isNotBlank()) file.writeText(config) else file.delete()
    }
}

sealed interface ExtraPeersSideEffect {
    data object Saved : ExtraPeersSideEffect
}
