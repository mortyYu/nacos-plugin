/*
 * Copyright 1999-2021 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.alibaba.nacos.plugin.encryption;

import com.alibaba.nacos.api.utils.StringUtils;
import com.alibaba.nacos.common.codec.Base64;
import com.alibaba.nacos.plugin.encryption.spi.EncryptionPluginService;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.paddings.ZeroBytePadding;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;

public class SM4EncryptionPluginService implements EncryptionPluginService {


    private static final String ALGORITHM_NAME = "SM4";
    private static final int DEFAULT_KEY_SIZE = 128;
    private static final Logger LOGGER = LoggerFactory.getLogger(SM4EncryptionPluginService.class);

    static {
        Security.addProvider(new BouncyCastleProvider());
    }


    @Override
    public String encrypt(String secretKey, String content) {
        if (StringUtils.isBlank(secretKey)) {
            return content;
        }
        try{
            byte[] keyBytes = Base64.decodeBase64(secretKey.getBytes(StandardCharsets.UTF_8));
            byte[] dataBytes = content.getBytes(StandardCharsets.UTF_8);

            SM4Engine engine = new SM4Engine();
            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(engine, new ZeroBytePadding());
            cipher.init(true, new KeyParameter(keyBytes));

            byte[] output = new byte[cipher.getOutputSize(dataBytes.length)];
            int length = cipher.processBytes(dataBytes, 0, dataBytes.length, output, 0);
            length += cipher.doFinal(output, length);

            byte[] encrypted = new byte[length];
            System.arraycopy(output, 0, encrypted, 0, length);
            return new String(Base64.encodeBase64(encrypted), StandardCharsets.UTF_8);
        }catch (Exception e){
            LOGGER.error("[SM4EncryptionPluginService] encrypt error", e);
        }

        return content;
    }

    @Override
    public String decrypt(String secretKey, String content) {
        if (StringUtils.isBlank(secretKey)) {
            return content;
        }
        try{
            byte[] keyBytes = Base64.decodeBase64(secretKey.getBytes(StandardCharsets.UTF_8));
            byte[] encryptedBytes = Base64.decodeBase64(content.getBytes(StandardCharsets.UTF_8));

            SM4Engine engine = new SM4Engine();
            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(engine, new ZeroBytePadding());
            cipher.init(false, new KeyParameter(keyBytes));

            byte[] output = new byte[cipher.getOutputSize(encryptedBytes.length)];
            int length = cipher.processBytes(encryptedBytes, 0, encryptedBytes.length, output, 0);
            length += cipher.doFinal(output, length);

            byte[] decrypted = new byte[length];
            System.arraycopy(output, 0, decrypted, 0, length);
            return new String(decrypted, StandardCharsets.UTF_8);

        } catch (Exception e) {
            LOGGER.error("[SM4decryptionPluginService] encrypt error", e);
        }
        return content;
    }

    @Override
    public String generateSecretKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("SM4", "BC");
            keyGenerator.init(DEFAULT_KEY_SIZE, new SecureRandom());
            SecretKey secretKey = keyGenerator.generateKey();
            return new String(Base64.encodeBase64(secretKey.getEncoded()), StandardCharsets.UTF_8);
        } catch (Exception e) {
            LOGGER.error("[SM4EncryptionPluginService] generateSecretKey error", e);
        }
        return "";
    }

    @Override
    public String algorithmName() {
        return ALGORITHM_NAME;
    }

    @Override
    public String encryptSecretKey(String secretKey) {
        return "";
    }

    @Override
    public String decryptSecretKey(String secretKey) {
        return "";
    }

}
