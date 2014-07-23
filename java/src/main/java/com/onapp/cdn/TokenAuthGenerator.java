package com.onapp.cdn;

import static com.google.common.net.InternetDomainName.isValid;
import static java.lang.Long.parseLong;
import static java.lang.String.format;
import static org.apache.shiro.codec.Hex.decode;
import static org.apache.shiro.util.StringUtils.hasText;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

import org.apache.shiro.crypto.BlowfishCipherService;
import org.apache.shiro.crypto.CipherService;
import org.apache.shiro.crypto.CryptoException;
import org.apache.shiro.crypto.OperationMode;
import org.apache.shiro.crypto.PaddingScheme;

/**
 * Tool to generate / decrypt token.
 * 
 * @author kwshoo
 * @version 20140723
 */
public class TokenAuthGenerator {
    
    private static CipherService cipherService = new BlowfishCipherService() {{
        setMode(OperationMode.ECB);
        setPaddingScheme(PaddingScheme.PKCS5);
    }};
    
    public static final String PARAM_EXPIRE    = "expire";
    public static final String PARAM_REF_ALLOW = "ref_allow";
    public static final String PARAM_REF_DENY  = "ref_deny";
    
    @SuppressWarnings("serial")
    private static final Set<String> SUPPORTED_PARAMS = new HashSet<String>() {{
        add(PARAM_EXPIRE);
        add(PARAM_REF_ALLOW);
        add(PARAM_REF_DENY);
    }};
    
    public static String encrypt(String key, String parameters) throws CryptoException {
        return _encrypt(key, parameters, true);
    }
    
    /**
     * NOTE: DO NOT USE THIS - FOR TESTING PURPOSE.
     */
    public static String _encrypt(String key, String parameters, boolean isValidateSecurityParams) throws CryptoException {
        parseSecurityParameters(parameters, isValidateSecurityParams);
        return cipherService.encrypt(parameters.getBytes(), key.getBytes()).toHex();
    }
    
    public static String decrypt(String key, String encryptedStr) throws CryptoException {
        return new String(cipherService.decrypt(decode(encryptedStr), key.getBytes()).getBytes());
    }
    
    public static Map<String, Object> parseSecurityParameters(String parameters) {
        return parseSecurityParameters(parameters, true);
    }
    
    /**
     * Given a string of security parameters, it will be parsed and return a map of result.
     * 
     * Example of returned result:
     * <pre>
     *   
     * </pre>
     */
    public static Map<String, Object> parseSecurityParameters(String parameters, boolean isValidateSecurityParams) {
        if (!hasText(parameters))
            throw new IllegalArgumentException("Parameters must not be empty");
        
        StringTokenizer token = new StringTokenizer(parameters, "&");
        Map<String, Object> map = new HashMap<String, Object>();
        while (token.hasMoreTokens()) {
            String[] strArray = token.nextToken().split("=");
            if (strArray.length != 2 || (!hasText(strArray[0]) || !hasText(strArray[1])))
                throw new IllegalArgumentException("Malformed key/value pair");
            
            String paramKey = strArray[0];
            String paramValue = strArray[1];
            
            // Supported param keys check
            if (!isParameterSupported(paramKey))
                throw new UnsupportedOperationException(format("Unsupported parameter '%s'", paramKey));
            
            // Duplication check
            if (!map.containsKey(paramKey)) {
                map.put(paramKey, parse(paramKey, paramValue, isValidateSecurityParams));
            } else {
                throw new IllegalArgumentException(format("Duplicate key '%s' is not allowed", strArray[0]));
            }
        }
        
        return map;
    }
    
    public static Object parse(String key, String value, boolean isValidate) {
        if (PARAM_EXPIRE.equals(key)) {
            long expire = parseLong(value);
            if (isValidate && expire <= (System.currentTimeMillis() / 1000)) {
                throw new IllegalArgumentException("Parameter 'expire' should not be a past date");
            }
            return new Date(expire * 1000);
        } else if (PARAM_REF_ALLOW.equals(key) || PARAM_REF_DENY.equals(key)) {
            String refs = value;
            String[] refArr = refs.split(",");
            List<String> refList = new ArrayList<String>();
            for (String ref : refArr) {
                if (ref.equals("MISSING"))
                    continue;
                
                if (isValidate)
                    validateReferrer(ref);
                refList.add(ref);
            }
            return refList.toArray(new String[0]);
        } else {
            throw new UnsupportedOperationException(format("Unsupported parameter '%s'", key));
        }
    }
    
    public static void validateReferrer(String ref) {
        URL url = null;
        String temp = "http://" + ref;
        
        if (!hasText(ref)) {
            throw new IllegalArgumentException("Referrer must not be blank");
        }
        
        if (ref.startsWith(" ") || ref.endsWith(" "))
            throw new IllegalArgumentException("Referrer must not be start/end with space(s)");
        
        if (ref.contains("*")) {
            if (!ref.startsWith("*.") || ref.lastIndexOf("*") > 0) {
                throw new IllegalArgumentException("Wildcard usage(*.DOMAIN) for referrer must exist only at the beginning of a domain");
            }
            
            // So we can test the ref validity with URL constructor =P
            temp = temp.replace("*", "temp");
        }
        
        // Fail if referrer contains protocol
        try {
            url = new URL(ref);
            if (hasText(url.getProtocol())) {
                throw new IllegalArgumentException(format("Referrer '%s' must not contain protocol", ref));
            }
        } catch (MalformedURLException e) {}
        
        try {
            url = new URL(temp);
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException(format("Referrer '%s' is malformed (RFC 2396)", ref));
        }
        
        if (!isValid(url.getHost())) {
            throw new IllegalArgumentException(format("Referrer '%s' hostname is invalid(RFC 3490)", ref));
        }
        
        if (url.getPort() != -1) {
            throw new IllegalArgumentException(format("Referrer must not contain port number", ref));
        }
    }
    
    public static boolean isParameterSupported(String parameterKey) {
        return SUPPORTED_PARAMS.contains(parameterKey); 
    }
    
    public static void main(String[] args) throws Exception {
        if (args.length != 3) 
            throw new IllegalArgumentException("Expected 3 arguments. Refer to README for usage");
        if (!"encrypt".equals(args[0]) && !"decrypt".equals(args[0])) 
            throw new IllegalArgumentException("Invalid action. Refer to README for usage");
        
        if ("encrypt".equals(args[0])) {
            String key = args[1];
            String parameters = args[2];
            String encryptedStr = encrypt(key, parameters);
            System.out.println("token=" + encryptedStr);
            return;
        } else if ("decrypt".equals(args[0])) {
            String key = args[1];
            String encryptedStr = args[2];
            System.out.println("security parameters=" + decrypt(key, encryptedStr));
            return;
        }
    }
}
