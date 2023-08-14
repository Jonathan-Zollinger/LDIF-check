package com.ldifcheck.cmd;

import com.ldifcheck.util.LdapUtils;
import com.ldifcheck.util.PicoCliValidation;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldif.LDIFException;
import com.unboundid.ldif.LDIFReader;
import org.fusesource.jansi.AnsiConsole;
import picocli.CommandLine;

import javax.naming.*;
import javax.naming.directory.DirContext;
import javax.naming.ldap.InitialLdapContext;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@CommandLine.Command(name = "ldifcheck",
        description = "validates an ldif file against a directory service.",
        mixinStandardHelpOptions = true,
        versionProvider = LdifCheck.ManifestVersionProvider.class,
        showDefaultValues = true)
public class LdifCheck implements Runnable {

    String IP, ADMIN_DN, ADMIN_SECRET, TRUST_STORE, TRUST_STORE_PASSWORD, SSL_PORT;
    Pattern attributeNamePattern = Pattern.compile("NAME '([^']*)'");
    @CommandLine.Spec
    CommandLine.Model.CommandSpec spec;

    DirContext context;
    LdapUtils ldapUtils;

    @CommandLine.Option(
            names = "--file",
            description = "ldif file to be validated.",
            defaultValue = ""
    )
    Path ldifFile;

    @CommandLine.Option(
            names = "--env",
            description = "environment variables with which to access eDirectory",
            defaultValue = ".env"
    )
    Path envFile;

    public static void main(String[] args) {
        // To avoid warnings about Log42 not being in classpath
        // See https://poi.apache.org/components/logging.html for more information (Specifically the Log4J SimpleLogger section)
        System.getProperties().setProperty("log4j2.loggerContextFactory", "org.apache.logging.log4j.simple.SimpleLoggerContextFactory");

        AnsiConsole.systemInstall();
        CommandLine cmd = new CommandLine(new LdifCheck());
        int exitCode = cmd.execute(args);
        AnsiConsole.systemUninstall();
        System.exit(exitCode);
    }

    @Override
    public void run() {
        getEnv();
        initiateLdapConnection();
        ldapUtils = new LdapUtils(context);
        List<Entry> ldifEntries = readLdifFile(ldifFile);
        logBadAttributes(ldifEntries);
        reportOrphanedAttributes(ldifEntries.toArray(new Entry[0]));
    }

    void reportOrphanedAttributes(Entry... ldifEntries) {
        NamingEnumeration<Binding> actualAttributesEnumeration;
        try {
            actualAttributesEnumeration = context.getSchema("").listBindings("attributeDefinition");
        } catch (NamingException e) {
            throw new RuntimeException("Failed to query all attribute definition bindings", e);
        }
        Set<String> actualAttributeNames = new HashSet<>();
        while(actualAttributesEnumeration.hasMoreElements()){
            actualAttributeNames.add(actualAttributesEnumeration.nextElement().getName());
        }
        Set<Entry> badAttributes = Arrays.stream(ldifEntries)
                .filter(entry -> {
                    String poorlyParsedString = entry.getAttributeValue("attributeTypes");
                    Matcher nameMatcher = attributeNamePattern.matcher(poorlyParsedString);
                    if (nameMatcher.find()){
                        return actualAttributeNames.contains(nameMatcher.group(1));//17th iteration causes null pointer?
                    }
                    return false;
                })
                .collect(Collectors.toSet());
        if (badAttributes.isEmpty()){
            return;
        }
        for (Entry entry: badAttributes){
            try (FileOutputStream outputStream = new FileOutputStream("orphaned-attributes.ldif")) {
                outputStream.write(entry.toLDIFString().getBytes());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    void logBadAttributes(List<Entry> ldifEntries) {
        Set<String> badAttributeNames = new HashSet<>();
        for (Entry ldifEntry : ldifEntries) {
            badAttributeNames.addAll(getExcessAttributeNames(ldifEntry));
        }
        try(FileOutputStream outputStream = new FileOutputStream("bad-attribute-names.ldif")) {
            outputStream.write(String.join(System.lineSeparator(), badAttributeNames).getBytes());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    String attributeParser(Attribute attribute){
        String unhelpfulAttributeLine = attribute.getValue();
        Pattern namePattern = Pattern.compile("NAME '([^']*)'");
        Matcher nameMatcher = namePattern.matcher(unhelpfulAttributeLine);
        if (nameMatcher.find()) {
            System.out.println("NAME: " + nameMatcher.group(1));
        }

        // Extracting SYNTAX
        Pattern syntaxPattern = Pattern.compile("SYNTAX (\\S*)");
        Matcher syntaxMatcher = syntaxPattern.matcher(unhelpfulAttributeLine);
        if (syntaxMatcher.find()) {
            System.out.println("SYNTAX: " + syntaxMatcher.group(1));
        }

        // Extracting X-NDS properties
        Pattern xNdsPattern = Pattern.compile("(X-NDS_\\S*) '([^']*)'");
        Matcher xNdsMatcher = xNdsPattern.matcher(unhelpfulAttributeLine);
        while (xNdsMatcher.find()) {
            System.out.println(xNdsMatcher.group(1) + ": " + xNdsMatcher.group(2));
        }

        List<String> prettyfiedString = new ArrayList<>(Collections.singletonList("attributeTypes: ("));
        String[] sanitizedOutput = attribute.getValue()
                .substring(1, attribute.getValue().length() - 1)
                .trim()
                .split(" ");
        int i = 0;
        while (i < sanitizedOutput.length -1) {
            if (sanitizedOutput[i].contains("oid")){
                prettyfiedString.add("\t" + sanitizedOutput[i]);
                i ++;
            }else {
                prettyfiedString.add(String.format("\t%s: %s", sanitizedOutput[i], sanitizedOutput[i+1]));
                i += 2;
            }
        }
        prettyfiedString.add("\t)");
        return String.join(System.lineSeparator(), prettyfiedString);
    }



    List<Entry> readLdifFile(Path ldifFile) {
        List<Entry> ldifRecord = new ArrayList<>();
        try (InputStream inputStream = Files.newInputStream(ldifFile)) {
            LDIFReader reader = new LDIFReader(inputStream);

            while (true){
                Entry thisEntry = reader.readEntry();
                if (thisEntry != null){
                    ldifRecord.add(thisEntry);
                }else {
                    break;
                }
            }
        } catch (IOException | LDIFException e) {
            throw new RuntimeException(e);
        }
        return ldifRecord;
    }

    void getEnv() {
        PicoCliValidation.fileExistsAndIsReadable(spec, envFile);
        ResourceBundle envProperties;
        try (FileInputStream propertiesStream = new FileInputStream(envFile.toFile())) {
            envProperties = new PropertyResourceBundle(propertiesStream);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        List<String> missingProperties = Stream.of("ADMIN_DN", "ADMIN_SECRET", "TRUST_STORE", "TRUST_STORE_PASSWORD", "SSL_PORT", "IP")
                .filter(property -> !envProperties.containsKey(property)).collect(Collectors.toList());
        if (!missingProperties.isEmpty()) {
            throw new IllegalStateException("The env file is missing the following properties:" +
                    "\n\t" + String.join("\n\t", missingProperties));
        }
        IP = envProperties.getString("IP");
        ADMIN_DN = envProperties.getString("ADMIN_DN");
        ADMIN_SECRET = envProperties.getString("ADMIN_SECRET");
        TRUST_STORE = envProperties.getString("TRUST_STORE");
        TRUST_STORE_PASSWORD = envProperties.getString("TRUST_STORE_PASSWORD");
        SSL_PORT = envProperties.getString("SSL_PORT");
    }

    void initiateLdapConnection() {
        getEnv();
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
        try {
            context = new InitialLdapContext(env, null);
        } catch (NamingException e) {
            throw new RuntimeException(e);
        }
    }

    Set<String> getExcessAttributeNames(Entry ldifEntry) {
        if (null == ldifEntry.getObjectClassValues()) {
            throw new RuntimeException("Ldap Entry doesn't contain an object class value.\n" + ldifEntry.toLDIFString() );
        }
        Set<String> permittedValues = ldapUtils.getBasicAttributeValues(true, Arrays.stream(ldifEntry.getObjectClassValues())
                .collect(Collectors.toSet()), "must", "may");
        return ldifEntry.getAttributes()
                .stream()
                .map(com.unboundid.ldap.sdk.Attribute::getName)
                .filter(attribute -> !permittedValues.contains(attribute))
                .collect(Collectors.toSet());
    }

    public static class ManifestVersionProvider implements CommandLine.IVersionProvider {
        public String[] getVersion() {
            return new String[]{LdifCheck.class.getPackage().getImplementationVersion()};
        }
    }
}
