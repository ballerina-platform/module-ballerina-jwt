/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.ballerinalang.stdlib.jwt;

import io.ballerina.runtime.api.creators.ErrorCreator;
import io.ballerina.runtime.api.creators.ValueCreator;
import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BArray;
import io.ballerina.runtime.api.values.BError;
import io.ballerina.runtime.api.values.BString;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * JWT related utility functions.
 *
 * @since 2.0.0
 */
public class JwtUtils {

    public static BString encodeBase64Url(BArray input) {
        byte[] encodedValue = Base64.getUrlEncoder().withoutPadding().encode(input.getBytes());
        return StringUtils.fromString(new String(encodedValue, StandardCharsets.ISO_8859_1));
    }

    public static Object decodeBase64Url(BString input) {
        try {
            byte[] output = Base64.getUrlDecoder().decode(input.getValue());
            return ValueCreator.createArrayValue(output);
        } catch (IllegalArgumentException e) {
            return createError("Input is not a valid Base64 URL encoded value. " + e.getMessage());
        }
    }

    public static BError createError(String errMsg) {
        return ErrorCreator.createDistinctError(JwtConstants.JWT_ERROR_TYPE, ModuleUtils.getModule(),
                                                StringUtils.fromString(errMsg));
    }
}
