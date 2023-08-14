package com.ldifcheck.cmd;

import com.unboundid.ldap.sdk.Entry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.naming.Context;
import java.io.File;
import java.nio.file.Paths;
import java.util.Hashtable;
import java.util.List;

class SchemaCheckTest {
    String testResourcesDir = String.join(String.valueOf(File.separatorChar), "src test resources".split(" "));
    LdifCheck schemaCheck;
    String IP, SERVER_CONTEXT, SERVER_NAME, TREE_NAME, ADMIN_DN, ADMIN_SECRET, TRUST_STORE, TRUST_STORE_PASSWORD;
    int NCP_PORT,  LDAP_PORT,  SSL_PORT,  HTTP_PORT,  HTTPS_PORT;

    @BeforeEach
    void setUp() {
        System.setProperty("com.sun.jndi.ldap.object.disableEndpointIdentification","true");
        schemaCheck = new LdifCheck();
    }

    @AfterEach
    void tearDown() {
        System.setProperty("com.sun.jndi.ldap.object.disableEndpointIdentification","false");
    }

    void readEnv() {
        schemaCheck.envFile = Paths.get(testResourcesDir +File.separatorChar + ".env");
    }

    Hashtable<String,String> getEnv() {
        NCP_PORT=2524;
        LDAP_PORT=1389;
        SSL_PORT=1636;
        HTTP_PORT=1028;
        HTTPS_PORT=1030;
        IP="172.17.2.139";
        SERVER_CONTEXT="novell";
        SERVER_NAME="IDM-unit";
        TREE_NAME="trivir";
        ADMIN_DN="cn=admin,o=services";
        ADMIN_SECRET="trivir";
        String[] trustStorePath = new String[]{System.getProperty("java.home"),"lib","security","cacerts"};
        TRUST_STORE = String.join(String.valueOf(File.separatorChar),trustStorePath);
        TRUST_STORE_PASSWORD = "changeit";

        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put("com.sun.jndi.ldap.connect.pool", "true");  //CP CHANGE TO DISABLE LDAP CONNECTION POOL
        env.put("com.sun.jndi.ldap.connect.pool.protocol", "plain ssl");
        env.put("com.sun.jndi.ldap.connect.pool.timeout", "1000");
        env.put("com.sun.jndi.ldap.connect.pool.maxsize", "3");
        env.put("com.sun.jndi.ldap.connect.pool.prefsize", "1");
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, ADMIN_DN);
        env.put(Context.SECURITY_CREDENTIALS, ADMIN_SECRET);
        env.put("com.sun.jndi.ldap.connect.timeout", "50000");
        env.put(Context.REFERRAL, "follow");
        env.put(Context.PROVIDER_URL, "ldaps://" + IP + ":" + SSL_PORT);
        env.put("javax.net.ssl.trustStore", TRUST_STORE);
        env.put("javax.net.ssl.trustStorePassword", TRUST_STORE_PASSWORD);
        return env;
    }

    @Test
    void logAttributesNotInServer() {
        readEnv();
        schemaCheck.initiateLdapConnection();
        schemaCheck.ldifFile = Paths.get(String.join(String.valueOf(File.separatorChar),
                (testResourcesDir + " env IDV-Schema-Greenlnk.ldif").split(" ")));
        List<Entry> theseEntries = schemaCheck.readLdifFile(schemaCheck.ldifFile);
        schemaCheck.reportOrphanedAttributes(theseEntries.toArray(new Entry[0]));
    }






//    /**
//     * Validates LdapConnector.getAttributeValuesByID() returns the required attribute names when requesting 'must' attributes.
//     *
//     * @throws Exception inherited from the `writeCertificatesToKeyStore` call when creating an eDir connector
//     */
//    public void testGetBasicAttributeNames() throws Exception {
//        Map<String, Collection<String>> user = Stream.of(new String[][]{
//                {"sn", faker.name().name()},
//                {"cn", faker.name().username()},
//                {"objectClass", "inetOrgPerson"}
//        }).collect(Collectors.toMap(data -> data[0], data -> Collections.singleton(data[1])));
//
//        connector.getBasicAttributeValues(true, (Set<String>) user.get("objectClass"), "must");
//        assertEquals("Expected user's attributes to be all and no more than the 'must' attributes",
//                connector.getBasicAttributeValues(true, (Set<String>) user.get("objectClass"), "must"),user.keySet());
//    }
//
//    /**
//     * Validates that LdapConnector.validateAttributeNames() returns true when all must attributes are
//     * included in the user argument.
//     *
//     * @throws Exception inherited from the `writeCertificatesToKeyStore` call when creating an eDir connector
//     */
//    public void testValidateAttributeNames() throws Exception {
//        Map<String, Collection<String>> user = LdapUtil.getEdirUser();
//        assertTrue("Expected attributes to be valid", connector.opValidateAttributeNames(user));
//    }
//
//    /**
//     * Validates that LdapConnector.validateAttributeNames() returns false when an  invalid attribute name is used.
//     *
//     * @throws Exception inherited from the `writeCertificatesToKeyStore` call when creating an eDir connector
//     */
//    public void testValidateAttributeNamesFails() throws Exception {
//        Map<String, Collection<String>> user = getEdirUser();
//        connector.opAddObject(user);
//        user.put("HomeAddress", Collections.singleton(faker.chuckNorris().fact())); //TODO candidate for more attributes testing
//        assertFalse("Expected attributes to be invalid", connector.opValidateAttributeNames(user));
//    }
//
//    /**
//     * Validates LdapConnector.GetMissingRequiredAttributeNames returns missing "cn" and "sn" attributes.
//     *
//     * @throws Exception inherited from the `writeCertificatesToKeyStore` call when creating an eDir connector
//     */
//    public void testGetMissingRequiredAttributeNames() throws Exception {
//        Map<String, Collection<String>> user = getEdirUser();
//        Set<String> missingRequiredAttribute = new HashSet<>(Arrays.asList("cn", "sn"));
//        user.remove("cn");
//        user.remove("sn");
//        assertEquals(String.format("Expected \"%s\" to be listed as a missing attribute\n\t", missingRequiredAttribute),
//                missingRequiredAttribute, connector.opGetMissingRequiredAttributeNames(user));
//    }
//
//    /**
//     * Validates LdapConnector.getMissingRequiredAttributeNames() returns an empty object rather than a null value.
//     *
//     * @throws Exception inherited from the `writeCertificatesToKeyStore` call when creating an eDir connector
//     */
//    public void testGetZeroMissingRequiredAttributeNames() throws Exception {
//        Map<String, Collection<String>> user = getEdirUser();
//        assertEquals("Expected 'getMissingRequiredAttributeNames()' to return an empty Set<String> object",
//                new HashSet<String>(), connector.opGetMissingRequiredAttributeNames(user));
//    }
//
//    /**
//     * Validates any bad attribute names given to LdapConnector.opGetInvalidAttributeNames are returned as invalid attribute names.
//     *
//     * @throws Exception inherited from the `writeCertificatesToKeyStore` call when creating an eDir connector
//     */
//    public void testGetInvalidAttributeNames() throws Exception {
//        Map<String, Collection<String>> user = Stream.of(new String[][]{
//                {"objectClass", "user"},
//                {"Password", faker.internet().password()},
//                {"Favorite Person", faker.slackEmoji().celebration()},
//                {"User Password", faker.internet().password()}
//        }).collect(Collectors.toMap(data -> data[0], data -> Collections.singleton(data[1])));
//        assertEquals("expected 3 attribute names to be flagged as invalid.",
//                new HashSet<>(Arrays.asList("Password","Favorite Person","User Password"))
//                , .opGetInvalidAttributeNames(user));
//
//    }
//
//    public void testGetXndsMappedObjectClassName() throws Exception {
//        Map<String, String> testData = new HashMap<>(Stream.of(new String[][]{
//                {"User", "inetOrgPerson"},
//                {"Alias", "aliasObject"},
//                {"certificationAuthorityVer2", "certificationAuthority-V2"},
//                {"LDAP Group", "ldapGroup"},
//                {"LDAP Server", "ldapServer"},
//                {"NCP Server", "ncpServer"},
//                {"Group","groupOfNames"}
//        }).collect(Collectors.toMap(map -> map[0], map -> map[1])));
//
//        for (String attributeName:testData.keySet() ) {
//            assertEquals(new HashSet<>(Collections.singleton(testData.get(attributeName)))
//                    , connector.getXndsMappedObjectClassName(attributeName));
//        }
//        System.out.println(connector.getXndsMappedObjectClassName("Description"));
//    }
}