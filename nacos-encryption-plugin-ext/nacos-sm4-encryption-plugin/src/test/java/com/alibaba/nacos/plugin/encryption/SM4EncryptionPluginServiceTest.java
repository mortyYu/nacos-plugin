package com.alibaba.nacos.plugin.encryption;

import com.alibaba.nacos.plugin.enncryption.SM4EncryptionPluginService;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class SM4EncryptionPluginServiceTest {

    private SM4EncryptionPluginService sm4EncryptionPluginService;

    private static final String CONTENT = "测试内容";

    @Before
    public void setUp() throws Exception {
        sm4EncryptionPluginService = new SM4EncryptionPluginService();
    }

    @Test
    public void testEncrypt() {
        String secretKey = sm4EncryptionPluginService.generateSecretKey();
        String encrypt = sm4EncryptionPluginService.encrypt(secretKey, CONTENT);
        Assert.assertNotNull(encrypt);
    }

    @Test
    public void testDecrypt() {
        String secretKey = sm4EncryptionPluginService.generateSecretKey();
        String encrypt = sm4EncryptionPluginService.encrypt(secretKey, CONTENT);
        String decrypt = sm4EncryptionPluginService.decrypt(secretKey, encrypt);
        Assert.assertEquals(CONTENT, decrypt);
    }

    @Test
    public void testGenerateSecretKey() {
        String secretKey = sm4EncryptionPluginService.generateSecretKey();
        Assert.assertNotNull(secretKey);
    }

    @Test
    public void testNamed() {
        String named = sm4EncryptionPluginService.algorithmName();
        Assert.assertEquals(named, "SM4");
    }
}
