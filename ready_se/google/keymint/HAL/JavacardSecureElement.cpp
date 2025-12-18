/*
 * Copyright 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "javacard.keymint.device.strongbox-impl"
#include "JavacardSecureElement.h"

#include <algorithm>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <regex.h>
#include <string>
#include <vector>

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <keymaster/android_keymaster_messages.h>

#include "keymint_utils.h"

namespace keymint::javacard {

keymaster_error_t JavacardSecureElement::initializeJavacard() {
    // Provision Attestation Ids at first
    sendAttestationIds();
    Array request;
    request.add(Uint(getOsVersion()));
    request.add(Uint(getOsPatchlevel()));
    request.add(Uint(getVendorPatchlevel()));
    auto [item, err] = sendRequest(Instruction::INS_INIT_STRONGBOX_CMD, request);
    return err;
}

keymaster_error_t JavacardSecureElement::sendAttestationIds() {
    static constexpr char brand_prop_name[] = "ro.product.brand";
    static constexpr char device_prop_name[] = "ro.product.device";
    static constexpr char product_prop_name[] = "ro.product.name";
    static constexpr char serial_prop_name[] = "ro.serialno";
    static constexpr char manufacturer_prop_name[] = "ro.product.manufacturer";
    static constexpr char model_prop_name[] = "ro.product.model";

    std::string brand_prop_value = android::base::GetProperty(brand_prop_name, "");
    std::string device_prop_value = android::base::GetProperty(device_prop_name, "");
    std::string product_prop_value = android::base::GetProperty(product_prop_name, "");
    std::string serial_prop_value = android::base::GetProperty(serial_prop_name, "");
    std::string manufacturer_prop_value = android::base::GetProperty(manufacturer_prop_name, "");
    std::string model_prop_value = android::base::GetProperty(model_prop_name, "");

    std::string imei_value = "867400022047199";
    std::string imei2_value = "867400022047199";
    std::string meid = "";
    std::map<keymaster_tag_t, std::string> attestation_ids = {
        {KM_TAG_ATTESTATION_ID_BRAND, brand_prop_value},
        {KM_TAG_ATTESTATION_ID_DEVICE, device_prop_value},
        {KM_TAG_ATTESTATION_ID_PRODUCT, product_prop_value},
        {KM_TAG_ATTESTATION_ID_SERIAL, serial_prop_value},
        {KM_TAG_ATTESTATION_ID_IMEI, imei_value},
        {KM_TAG_ATTESTATION_ID_MANUFACTURER, manufacturer_prop_value},
        {KM_TAG_ATTESTATION_ID_MODEL, model_prop_value},
        {KM_TAG_ATTESTATION_ID_SECOND_IMEI, imei2_value},
        {KM_TAG_ATTESTATION_ID_MEID, meid}};

    Map map;
    for (auto const& pair : attestation_ids) {
        map.add(static_cast<uint32_t>(pair.first),
                std::vector<uint8_t>(pair.second.begin(), pair.second.end()));
    }
    // construct cbor input.
    Array request;
    request.add(std::move(map));
    std::vector<uint8_t> command = request.encode();
    auto [item, err] = sendRequest(Instruction::INS_PROVISION_ATTEST_IDS_CMD, request);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Failed to provision attestation ids";
    }
    return err;
}

void JavacardSecureElement::setDeleteAllKeysPending() {
    isDeleteAllKeysPending = true;
}

void JavacardSecureElement::setEarlyBootEndedPending() {
    isEarlyBootEndedPending = true;
}

void JavacardSecureElement::sendPendingEvents() {
    if (isDeleteAllKeysPending) {
        auto [_, err] = sendRequest(Instruction::INS_DELETE_ALL_KEYS_CMD);
        if (err == KM_ERROR_OK) {
            isDeleteAllKeysPending = false;
        } else {
            LOG(ERROR) << "Error in sending deleteAllKeys.";
        }
    }

    if (isEarlyBootEndedPending) {
        auto [_, err] = sendRequest(Instruction::INS_EARLY_BOOT_ENDED_CMD);
        if (err == KM_ERROR_OK) {
            isEarlyBootEndedPending = false;
        } else {
            LOG(ERROR) << "Error in sending earlyBootEnded.";
        }
    }
}

keymaster_error_t JavacardSecureElement::constructApduMessage(Instruction& ins,
                                                              std::vector<uint8_t>& inputData,
                                                              std::vector<uint8_t>& apduOut) {
    apduOut.push_back(static_cast<uint8_t>(APDU_CLS));  // CLS
    apduOut.push_back(static_cast<uint8_t>(ins));       // INS
    apduOut.push_back(p1_);                             // P1
    apduOut.push_back(static_cast<uint8_t>(APDU_P2));   // P2

    if (USHRT_MAX >= inputData.size()) {
        // Send extended length APDU always as response size is not known to HAL.
        // Case 1: Lc > 0  CLS | INS | P1 | P2 | 00 | 2 bytes of Lc | CommandData | 2 bytes of Le
        // all set to 00. Case 2: Lc = 0  CLS | INS | P1 | P2 | 3 bytes of Le all set to 00.
        // Extended length 3 bytes, starts with 0x00
        apduOut.push_back(static_cast<uint8_t>(0x00));
        if (inputData.size() > 0) {
            apduOut.push_back(static_cast<uint8_t>(inputData.size() >> 8));
            apduOut.push_back(static_cast<uint8_t>(inputData.size() & 0xFF));
            // Data
            apduOut.insert(apduOut.end(), inputData.begin(), inputData.end());
        }
        // Expected length of output.
        // Accepting complete length of output every time.
        apduOut.push_back(static_cast<uint8_t>(0x00));
        apduOut.push_back(static_cast<uint8_t>(0x00));
    } else {
        LOG(ERROR) << "Error in constructApduMessage.";
        return (KM_ERROR_INVALID_INPUT_LENGTH);
    }
    return (KM_ERROR_OK);  // success
}

keymaster_error_t JavacardSecureElement::sendData(Instruction ins, std::vector<uint8_t>& inData,
                                                  std::vector<uint8_t>& response) {
    keymaster_error_t ret = KM_ERROR_UNKNOWN_ERROR;
    std::vector<uint8_t> apdu;

    ret = constructApduMessage(ins, inData, apdu);

    if (ret != KM_ERROR_OK) {
        return ret;
    }

    ret = transport_->sendData(apdu, response);
    if (ret != KM_ERROR_OK) {
        LOG(ERROR) << "Error in sending data in sendData. " << static_cast<int>(ret);
        return ret;
    }

    // Response size should be greater than 2. Cbor output data followed by two bytes of APDU
    // status.
    if ((response.size() <= 2) || (getApduStatus(response) != APDU_RESP_STATUS_OK)) {
        LOG(ERROR) << "Response of the sendData is wrong: response size = " << response.size()
                   << " apdu status = " << getApduStatus(response);
        return (KM_ERROR_UNKNOWN_ERROR);
    }
    // remove the status bytes
    response.pop_back();
    response.pop_back();
    return (KM_ERROR_OK);  // success
}

std::tuple<std::unique_ptr<Item>, keymaster_error_t>
JavacardSecureElement::sendRequest(Instruction ins, Array& request) {
    vector<uint8_t> response;
    // encode request
    std::vector<uint8_t> command = request.encode();
    auto sendError = sendData(ins, command, response);
    if (sendError != KM_ERROR_OK) {
        return {unique_ptr<Item>(nullptr), sendError};
    }
    // decode the response and send that back
    return cbor_.decodeData(response);
}

std::tuple<std::unique_ptr<Item>, keymaster_error_t>
JavacardSecureElement::sendRequest(Instruction ins, std::vector<uint8_t>& command) {
    vector<uint8_t> response;
    auto sendError = sendData(ins, command, response);
    if (sendError != KM_ERROR_OK) {
        return {unique_ptr<Item>(nullptr), sendError};
    }
    // decode the response and send that back
    return cbor_.decodeData(response);
}

std::tuple<std::unique_ptr<Item>, keymaster_error_t>
JavacardSecureElement::sendRequest(Instruction ins) {
    vector<uint8_t> response;
    vector<uint8_t> emptyRequest;
    auto sendError = sendData(ins, emptyRequest, response);
    if (sendError != KM_ERROR_OK) {
        return {unique_ptr<Item>(nullptr), sendError};
    }
    // decode the response and send that back
    return cbor_.decodeData(response);
}

}  // namespace keymint::javacard
