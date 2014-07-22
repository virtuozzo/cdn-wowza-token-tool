package com.onapp.cdn;

import static com.onapp.cdn.TokenAuthGenerator.PARAM_EXPIRE;
import static com.onapp.cdn.TokenAuthGenerator.PARAM_REF_ALLOW;
import static com.onapp.cdn.TokenAuthGenerator.PARAM_REF_DENY;
import static com.onapp.cdn.TokenAuthGenerator._encrypt;
import static com.onapp.cdn.TokenAuthGenerator.decrypt;
import static com.onapp.cdn.TokenAuthGenerator.encrypt;
import static com.onapp.cdn.TokenAuthGenerator.main;
import static com.onapp.cdn.TokenAuthGenerator.parseSecurityParameters;
import static java.lang.String.format;
import static java.util.Arrays.asList;
import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertTrue;

import java.util.Date;
import java.util.List;
import java.util.Map;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 * Unit tests for {@link TokenAuthGenerator}.
 * 
 * @author kwshoo
 * @version 20140722
 */
public class TokenAuthGeneratorTest {
    
    @Rule
    public ExpectedException thrown = ExpectedException.none();
    
    // ======================================================
    // encrypt
    // ======================================================
    @Test
    public void testEncrypt() {
        assertEquals(
                "110ea31ac69c09a2cb7854126719f5d3c3267d24c723eea5cbd99cc4d05426ab679a57015d4e48438c97b921652daec62de3829f8ff437e27449cfdfc2f1e5d9fc47f14e91a51ea7",
                _encrypt("samplekey", "expire=1356955399&ref_allow=*.TrustedDomain.com&ref_deny=Denied.com", false));
    }
    
    @Test
    public void testEncryptUnsupportedParameters() {
        thrown.expect(UnsupportedOperationException.class);
        thrown.expectMessage("Unsupported parameter 'some_unsupported_param'");
        encrypt("samplekey", "some_unsupported_param=123&ref_allow=*.TrustedDomain.com&ref_deny=Denied.com");
    }
    
    @Test
    public void testEncryptEmptyParamValue() {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("Malformed key/value pair");
        encrypt("samplekey", format("expire=%s&ref_allow=&ref_deny=Denied.com", getFutureDate()));
    }
    
    @Test
    public void testEncryptEmptyParamKey() {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("Malformed key/value pair");
        encrypt("samplekey", "=123&ref_allow=*.TrustedDomain.com&ref_deny=Denied.com");
    }
    
    @Test
    public void testEncryptEmptyParameters() {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("Parameters must not be empty");
        encrypt("samplekey", "");
    }
    
    // ======================================================
    // parseSecurityParameters
    // ======================================================
    
    @Test
    public void testParseSecurityParameters() {
        long fd = getFutureDate();
        Map<String, Object> rt = parseSecurityParameters(format("expire=%s&ref_allow=abc.com,*.TrustedDomain.com,&ref_deny=Denied.com", fd));
        
        assertEquals(3, rt.size());
        assertEquals(fd, ((Date) rt.get(PARAM_EXPIRE)).getTime());
        List<String> refAllowList = asList((String[]) rt.get(PARAM_REF_ALLOW));
        assertEquals(2, refAllowList.size());
        assertTrue(refAllowList.contains("abc.com"));
        assertTrue(refAllowList.contains("*.TrustedDomain.com"));
        List<String> refDenyList = asList((String[]) rt.get(PARAM_REF_DENY));
        assertEquals(1, refDenyList.size());
        assertTrue(refDenyList.contains("Denied.com"));
    }
    
    @Test
    public void testParseSecurityParametersEndWithSymbolAnd() {
        long fd = getFutureDate();
        Map<String, Object> rt = parseSecurityParameters(format("&expire=%s&ref_allow=abc.com,*.TrustedDomain.com,&&", fd));
        
        assertEquals(2, rt.size());
        assertEquals(fd, ((Date) rt.get(PARAM_EXPIRE)).getTime());
        List<String> refAllowList = asList((String[]) rt.get(PARAM_REF_ALLOW));
        assertEquals(2, refAllowList.size());
        assertTrue(refAllowList.contains("abc.com"));
        assertTrue(refAllowList.contains("*.TrustedDomain.com"));
        assertFalse(rt.containsKey(PARAM_REF_DENY));
    }
    
    @Test
    public void testParseSecurityParametersPastExpire() {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("Parameter 'expire' should not be a past date");
        long fd = new Date(new Date().getTime() - 99999).getTime();
        parseSecurityParameters(format("&expire=%s&ref_allow=abc.com,*.TrustedDomain.com,&&", fd));
    }
    
    @Test
    public void testParseSecurityParametersSpacesBeforeAndAfterReferrer() {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("Referrer must not be start/end with space(s)");
        parseSecurityParameters(format("&expire=%s&ref_allow= abc.com ,*.TrustedDomain.com,&&", getFutureDate()));
    }
    
    private long getFutureDate() {
        return new Date(new Date().getTime() + 99999).getTime();
    }
    
    // ======================================================
    // decrypt
    // ======================================================
    
    @Test
    public void testDecrypt() {
        assertEquals(
                "expire=1356955399&ref_allow=*.TrustedDomain.com&ref_deny=Denied.com",
                decrypt("samplekey",
                        "110ea31ac69c09a2cb7854126719f5d3c3267d24c723eea5cbd99cc4d05426ab679a57015d4e48438c97b921652daec62de3829f8ff437e27449cfdfc2f1e5d9fc47f14e91a51ea7"));
    }
    
    // ======================================================
    // main
    // ======================================================
    
    @Test
    public void testMainEncrypt() throws Exception {
        main(new String[] { "encrypt", "samplekey", format("expire=%s&ref_allow=*.TrustedDomain.com&ref_deny=Denied.com", getFutureDate()) });
    }
    
    @Test
    public void testMainDecrypt() throws Exception {
        main(new String[] { "decrypt", "samplekey", "110ea31ac69c09a2cb7854126719f5d3c3267d24c723eea5cbd99cc4d05426ab679a57015d4e48438c97b921652daec62de3829f8ff437e27449cfdfc2f1e5d9fc47f14e91a51ea7" });
    }
    
    @Test
    public void testMainUnmatchedNumberOfArguments() throws Exception {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("Expected 3 arguments. Refer to README for usage");
        main(new String[] { "encrypt" });
    }
    
    @Test
    public void testMainInvalidCommand() throws Exception {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("Invalid action. Refer to README for usage");
        main(new String[] { "invalid", "samplekey", "sample_params" });
    }
    
}