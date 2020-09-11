#include <base58.h>
#include <bls/bls.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <evo/specialtx.h>
#include <evo/providertx.h>
#include <evo/deterministicmns.h>
#include <evo/simplifiedmns.h>
#include <init.h>
#include <key_io.h>
#include <messagesigner.h>
#include <netbase.h>
#include <rpc/protocol.h>
#include <rpc/register.h>
#include <rpc/request.h>
#include <wallet/coincontrol.h>
#include <wallet/wallet.h>
#include <wallet/hdwallet.h>
#include <wallet/rpcwallet.h>
#include <util/moneystr.h>
#include <util/validation.h>
#include <validation.h>

#include <qt/guiconstants.h>
#include <qt/guiutil.h>
#include "masternode/masternode-meta.h"

#include <QMessageBox>
#include <QInputDialog>

// barrystyle 11092020

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
template<typename SpecialTxPayload>
void SignSpecialTxPayloadByHash(const CMutableTransaction& tx, SpecialTxPayload& payload, const CKey& key);

template<typename SpecialTxPayload>
void SignSpecialTxPayloadByString(const CMutableTransaction& tx, SpecialTxPayload& payload, const CKey& key);

template<typename SpecialTxPayload>
void SignSpecialTxPayloadByHash(const CMutableTransaction& tx, SpecialTxPayload& payload, const CBLSSecretKey& key);

template<typename SpecialTxPayload>
void SignSpecialTxPayloadByHash(const CMutableTransaction& tx, SpecialTxPayload& payload, const CKey& key);

template<typename SpecialTxPayload>
void UpdateSpecialTxInputsHash(const CMutableTransaction& tx, SpecialTxPayload& payload);

std::string SignAndSendSpecialTx(const CMutableTransaction& tx);
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Allows to specify Dash address or priv key. In case of Dash address, the priv key is taken from the wallet
static CKey ParsePrivKey(CWallet* pwallet, const std::string &strKeyOrAddress, bool allowAddresses = true) {
    CTxDestination dest = DecodeDestination(strKeyOrAddress);
    if (allowAddresses && IsValidDestination(dest)) {
#ifdef ENABLE_WALLET
        if (!pwallet) {
            throw std::runtime_error("addresses not supported when wallet is disabled");
        }
        EnsureWalletIsUnlocked(pwallet);
        CKeyID keyId;
        CKey key;
        keyId = GetKeyForDestination(*pwallet, dest);
        if (keyId.IsNull())
            throw std::runtime_error(strprintf("non-wallet or invalid address %s", strKeyOrAddress));
        if (!pwallet->GetKey(keyId, key))
            throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strKeyOrAddress + " is not known");
        return key;
#else//ENABLE_WALLET
        throw std::runtime_error("addresses not supported in no-wallet builds");
#endif//ENABLE_WALLET
    }

    CBitcoinSecret secret;
    if (!secret.SetString(strKeyOrAddress) || !secret.IsValid()) {
        throw std::runtime_error(strprintf("invalid priv-key/address %s", strKeyOrAddress));
    }
    return secret.GetKey();
}

static CKeyID ParsePubKeyIDFromAddress(const CWallet* pwallet, const std::string& strAddress, const std::string& paramName)
{
    CTxDestination address = DecodeDestination(strAddress);
    if (!IsValidDestination(address))
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be a valid P2PKH address, not %s", paramName, strAddress));

    CKeyID keyID = GetKeyForDestination(*pwallet, address);
    if (keyID.IsNull())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("%s does not refer to a key", strAddress));

    return keyID;
}

static CBLSPublicKey ParseBLSPubKey(const std::string& hexKey, const std::string& paramName)
{
    CBLSPublicKey pubKey;
    if (!pubKey.SetHexStr(hexKey)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be a valid BLS public key, not %s", paramName, hexKey));
    }
    return pubKey;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool createOneClickMasternode()
{
	//! get the wallet handle
	auto vpwallets = GetWallets();
	CHDWallet *phdw = nullptr;
	for (const auto &pw : vpwallets) {
		 phdw = GetParticlWallet(pw.get());
	     if (!phdw) {
			 continue;
		 }
	}

    //! doublecheck wallet
    if (!phdw) return false;
	auto locked_chain = phdw->chain().lock();

    //! build the protx
    CMutableTransaction tx;
    tx.SetType(TRANSACTION_PROVIDER_REGISTER);

    CProRegTx ptx;
    ptx.nVersion = CProRegTx::CURRENT_VERSION;

    //! get address from user
    bool ok = false;
    QString text = QInputDialog::getText(0, "oneClickMasternode", "masternode ipv4 address:port", QLineEdit::Normal, ":8193", &ok);
    if (!Lookup(text.toStdString().c_str(), ptx.addr, Params().GetDefaultPort(), false)) {
        return false;
    }

    //! locate mn-collateral
    int n = -1;
    uint256 hash = uint256();
    const CCoinControl *coinControl = nullptr;
    std::vector<COutput> vCoins;
    CTxDestination payoutAddress;
    phdw->AvailableCoins(*locked_chain, vCoins, true, coinControl);
    for (const COutput& out : vCoins) {
         if (out.tx->tx->vpout[out.i]->GetValue() == Params().GetConsensus().nMasternodeCollateral) {
             ExtractDestination(*out.tx->tx->vpout[out.i]->GetPScriptPubKey(), payoutAddress);
             hash = out.tx->tx->GetHash();
             n = out.i;
             break;
        }
    }

    //! make sure we got it
    if (n == -1) {
        QMessageBox messageBox;
        messageBox.critical(0,"Error","Could not locate a valid masternode collateral!");
        return false;
    }
    ptx.collateralOutpoint = COutPoint(hash, (uint32_t)n);
    phdw->LockCoin(ptx.collateralOutpoint);

    //! create keyset (ownerAddr)
    CPubKey newKeyOwner;
    if (0 != phdw->NewKeyFromAccount(newKeyOwner, false, false, false, false, "ownerAddr")) {
        QMessageBox messageBox;
        messageBox.critical(0,"Error","Could not create a owner address from wallet!");
        return false;
    }
    std::string ownerAddress = CBitcoinAddress(PKHash(newKeyOwner), false).ToString();

    //! create keyset (votingAddr)
    CPubKey newKeyVoter;
    if (0 != phdw->NewKeyFromAccount(newKeyVoter, false, false, false, false, "ownerAddr")) {
        QMessageBox messageBox;
        messageBox.critical(0,"Error","Could not create a voter address from wallet!");
        return false;
    }
    std::string voterAddress = CBitcoinAddress(PKHash(newKeyVoter), false).ToString();

    CBLSSecretKey sk;
    sk.MakeNewKey();
    std::string blsSecret = sk.ToString();
    std::string blsPubKey = sk.GetPublicKey().ToString();

    //! test everything we just retrieved
    CKey keyOwner = ParsePrivKey(phdw, ownerAddress, true);
    CBLSPublicKey pubKeyOperator = ParseBLSPubKey(blsPubKey, "operator-address");
    CKeyID keyIDVoting = ParsePubKeyIDFromAddress(phdw, voterAddress, "voter-address");

    ptx.nOperatorReward = 0;
    CTxDestination payoutDest = DecodeDestination(ownerAddress);
    if (!IsValidDestination(payoutDest)) {
        return false;
    }

    ptx.keyIDOwner = keyOwner.GetPubKey().GetID();
    ptx.pubKeyOperator = pubKeyOperator;
    ptx.keyIDVoting = keyIDVoting;
    ptx.scriptPayout = GetScriptForDestination(payoutAddress);
    CTxDestination fundDest = payoutDest;
    {
        Coin coin;
        if (!GetUTXOCoin(ptx.collateralOutpoint, coin)) {
            return false;
        }

        CKeyID keyID;
	    CTxDestination txDest;
        if (!ExtractDestination(coin.out.scriptPubKey, txDest)) {
            return false;
        }
	
        keyID = GetKeyForDestination(*phdw, txDest);
        if (keyID.IsNull()) {
            return false;
        }
	
        {
            CKey key;
            if (!phdw->GetKey(keyID, key)) {
                return false;
            }
            SignSpecialTxPayloadByString(tx, ptx, key);
            SetTxPayload(tx, ptx);
            SignAndSendSpecialTx(tx);
        }
    }

    return true;
}

