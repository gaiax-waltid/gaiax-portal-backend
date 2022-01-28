package id.walt.verifier.backend

import id.walt.auditor.VerificationPolicy
import id.walt.vclib.credentials.gaiax.ParticipantCredential
import id.walt.vclib.model.VerifiableCredential

class EthAddressVerificationPolicy(override val description: String = "Validates ETH address") : VerificationPolicy() {
    override fun doVerify(vc: VerifiableCredential): Boolean = when (vc) {
        is ParticipantCredential -> {
            kotlin.runCatching { "^0x[a-fA-F0-9]{40}$".toRegex().containsMatchIn(vc.credentialSubject!!.ethereumAddress!!) }
                .getOrDefault(false)
        }
        else -> true
    }

}