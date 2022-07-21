package com.changhr.utils.crypto.provider;

import javax.crypto.Cipher;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Security;
import java.util.Map;

/**
 * 反射开启无限制政策
 * 代码参考自：<a href="https://stackoverflow.com/questions/1179672/how-to-avoid-installing-unlimited-strength-jce-policy-files-when-deploying-an">installing unlimited strength jce policy</a>
 *
 * @author changhr2013
 * @date 2021/9/5
 */
public class UnlimitedHolder {

    public static volatile int unlimitedState = 0;

    private static final String CRYPTO_POLICY = "crypto.policy";

    private static final String UNLIMITED = "unlimited";

    private static final String AES_ALGORITHM = "AES";

    private static final int LIMIT_AES_LENGTH = 256;

    public static void init() {

        if (unlimitedState == 0) {

            try {
                // 将 crypto.policy 设置成 unlimited
                String property = Security.getProperty(CRYPTO_POLICY);
                if (!UNLIMITED.equalsIgnoreCase(property)) {
                    Security.setProperty(CRYPTO_POLICY, UNLIMITED);
                }

                int allowedKeyLength = Cipher.getMaxAllowedKeyLength(AES_ALGORITHM);
                if (allowedKeyLength < LIMIT_AES_LENGTH) {
                    /* Do the following, but with reflection to bypass access checks:
                      JceSecurity.isRestricted = false;
                      JceSecurity.defaultPolicy.perms.clear();
                      JceSecurity.defaultPolicy.add(CryptoAllPermission.INSTANCE);
                     */
                    final Class<?> jceSecurity = Class.forName("javax.crypto.JceSecurity");
                    final Class<?> cryptoPermissions = Class.forName("javax.crypto.CryptoPermissions");
                    final Class<?> cryptoAllPermission = Class.forName("javax.crypto.CryptoAllPermission");

                    // 反射移除了 isRestricted 的变量修饰符：final，然后将 isRestricted 赋值为 false
                    final Field isRestrictedField = jceSecurity.getDeclaredField("isRestricted");
                    isRestrictedField.setAccessible(true);
                    final Field modifiersField = Field.class.getDeclaredField("modifiers");
                    modifiersField.setAccessible(true);
                    modifiersField.setInt(isRestrictedField, isRestrictedField.getModifiers() & ~Modifier.FINAL);
                    isRestrictedField.set(null, false);

                    final Field defaultPolicyField = jceSecurity.getDeclaredField("defaultPolicy");
                    defaultPolicyField.setAccessible(true);
                    final PermissionCollection defaultPolicy = (PermissionCollection) defaultPolicyField.get(null);

                    final Field perms = cryptoPermissions.getDeclaredField("perms");
                    perms.setAccessible(true);
                    ((Map<?, ?>) perms.get(defaultPolicy)).clear();

                    final Field instance = cryptoAllPermission.getDeclaredField("INSTANCE");
                    instance.setAccessible(true);
                    defaultPolicy.add((Permission) instance.get(null));

                    allowedKeyLength = Cipher.getMaxAllowedKeyLength(AES_ALGORITHM);

                    if (allowedKeyLength >= LIMIT_AES_LENGTH) {
                        unlimitedState = 1;
                    }

                } else {
                    unlimitedState = 1;
                }

            } catch (Exception e) {
                throw new RuntimeException("auto open jce unlimited policy failed");
            }
        }
    }

}
