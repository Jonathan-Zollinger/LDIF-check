package com.ldifcheck.util;

import javax.naming.Binding;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class LdapUtils {

    DirContext context;

    public LdapUtils(DirContext context) {
        this.context = context;
    }


    /**
     * Returns the values for any basic attributes from attributesList whose name is case insensitively matched against basicAttributeNames.
     *
     * @param objectClass         names of object classes whose attributes are to be queried.
     * @param basicAttributeNames The names of the attributes whose basic attribute names are to be returned.
     * @return The names of the basic attributes assigned the provided basicAttributeNames in the given Attributes list.
     * @throws RuntimeException If a Naming Exception is encountered when querying the schema definition for any
     *                          attributes.
     */
    public Set<String> getBasicAttributeValues(Boolean recurse, Set<String> objectClass, String... basicAttributeNames) throws RuntimeException {
        List<Attributes> attributesList = getObjectClassAttributes(recurse, objectClass.toArray(new String[0]));
        Set<String> basicAttributeValues = new HashSet<>();
        for (Attributes attributes : attributesList) {
            NamingEnumeration<? extends Attribute> allResults = attributes.getAll();
            while (allResults.hasMoreElements()) {
                Attribute nextElement = allResults.nextElement();
                if (Arrays.stream(basicAttributeNames).anyMatch(nextElement.getID()::equalsIgnoreCase)) {
                    NamingEnumeration<?> ne;
                    try {
                        ne = nextElement.getAll();
                    } catch (NamingException e) {
                        throw new RuntimeException(String.format("Failed to query all elements in the \"%s\" element.", nextElement.getID()), e);
                    }
                    while (ne.hasMoreElements()) {
                        basicAttributeValues.add(String.valueOf(ne.nextElement()));
                    }
                }
            }
        }
        return basicAttributeValues;
    }

    /**
     * Retrieves the attributes of an object class as well as the attributes of the object class's super classes.
     *
     * @param objectClasses The name of the object class whose attributes will be returned
     * @return The attributes assigned to both an object class and its super classes.
     * @throws RuntimeException If a Naming Exception is encountered when querying the object class definition(s).
     */
    List<Attributes> getObjectClassAttributes(boolean recurse, String... objectClasses) throws RuntimeException {
        List<Attributes> searchResults = new ArrayList<>();
        for (String objectClass : objectClasses) {
            Attributes Attributes;
            try {
                Attributes = ((DirContext) context.getSchema("").lookup("ClassDefinition/" + objectClass)).getAttributes("");
                searchResults.add(Attributes);
            } catch (NamingException e) {
                try {
                    objectClass = getXndsMappedObjectClassName(objectClass).iterator().next();
                    Attributes = ((DirContext) context.getSchema("").lookup("ClassDefinition/" + objectClass)).getAttributes("");
                    searchResults.add(Attributes);
                } catch (NamingException ex) {
                    throw new RuntimeException(String.format("Failed to get Class definition for the \"%s\" object class.\n\t", objectClass), e);
                }
            }
            if (recurse) {
                if (null != Attributes.get("sup")) {
                    try {
                        searchResults.addAll(getObjectClassAttributes(true, (String) Attributes.get("sup").get()));
                    } catch (NamingException e) {
                        throw new RuntimeException(String.format("Failed to get the object class definition for the \"%s\" object " +
                                "class.\n\t", objectClass), e);
                    }
                }
            }
        }
        return searchResults;
    }

    /**
     * Returns the object class name associated with an LDAP synonym.
     *
     * @param xndsNames name of the LDAP synonym which is mapped in an object class's "x-nds_name" property
     * @return The object class associated with the LDAP synonym.
     * @throws RuntimeException if Naming exceptions are encountered when querying the ldap service.
     * @see <a href="https://docs.oracle.com/javase/jndi/tutorial/basics/directory/attrnames.html>JNDI Tutorial</a>
     */
    Set<String> getXndsMappedObjectClassName(String... xndsNames) throws RuntimeException {
        Set<String> xndsNamesSet = Arrays.stream(xndsNames).map(String::toLowerCase).collect(Collectors.toSet());
        Set<String> mappedObjectClass = new HashSet<>();
        NamingEnumeration<Binding> allTheObjectClasses;
        try {
            allTheObjectClasses = context.getSchema("").listBindings("classDefinition");
        } catch (NamingException e) {
            throw new RuntimeException("Failed to query all class definition bindings", e);
        }
        while (allTheObjectClasses.hasMoreElements()) {
            Binding thisBinding = allTheObjectClasses.nextElement();
            Set<String> returnedString;
            try {
                returnedString = getBasicAttributeValues(false, Collections.singleton(thisBinding.getName()), "x-nds_name", "x-nds_naming");
            } catch (RuntimeException e) {
                continue;
            }
            if (returnedString.stream().map(String::toLowerCase).anyMatch(xndsNamesSet::contains)) {
                mappedObjectClass.add(thisBinding.getName());
            }
        }
        return mappedObjectClass;
    }

    /**
     * Validates that the given attribute names are permitted for the object class's schema.
     *
     * @param attributes A map of non-repeating attributes where one entry is "objectClass" with a valid assignment.
     *                   The other keys in this map are the proposed attribute names that are being validated.
     * @return True if all required attributes are found in the provided attribute argument AND if all attribute
     * names in the provided attribute argument are listed as permitted attributes in the schema.
     * @throws RuntimeException If no objectClass is given or if a Naming Exception is encountered when querying the
     *                          schema class definition. This can happen if the objectClass assignment is invalid.
     */
    boolean validateAttributeNames(Map<String, Collection<String>> attributes) throws RuntimeException {
        if (!attributes.keySet().stream().map(String::toLowerCase).collect(Collectors.toSet()).contains("objectclass")) {
            throw new RuntimeException(String.format("Cannot call \"%s\" without an \"objectClass\" attribute.",
                    this.getClass().getEnclosingMethod().getName()));
        }
        return getBasicAttributeValues(true, (Set<String>) attributes.get("objectClass"), "must", "may")
                .containsAll(attributes.keySet().stream()
                        .filter(key -> !key.equalsIgnoreCase("dn"))
                        .collect(Collectors.toSet())) &&
                attributes.keySet().containsAll(getBasicAttributeValues(true, (Set<String>) attributes.get("objectClass"), "must"));
    }

    /**
     * Returns the names of attributes which are missing from the given attributes argument, but are required for
     * the given object class (and its super classes).
     *
     * @param attributes A map of non-repeating attributes where one entry is "objectClass" with a valid assignment.
     *                   The other keys in this map are the proposed attribute names that are being validated.
     * @return All attribute names that are required by the given objectClass's schema (and its super classes) but are
     * missing from the given attributes argument. This will return an empty string set if there are no missing attributes.
     * @throws RuntimeException If no objectClass is given or if a Naming Exception is encountered when querying the
     *                          schema class definition. This can happen if the objectClass assignment is invalid.
     */
    public Set<String> getMissingRequiredAttributeNames(Map<String, Collection<String>> attributes) throws RuntimeException {
        HashSet<String> requiredAttributes;
        if (attributes.containsKey("objectClass")) {
            requiredAttributes = (HashSet<String>) getBasicAttributeValues(true, (Set<String>) attributes.get("objectClass"), "must");
        } else {
            throw new RuntimeException("failed to find an object class with which to validate the provided attributes");
        }
        return requiredAttributes.stream()
                .filter(req -> attributes.keySet().stream().noneMatch(req::equalsIgnoreCase))
                .collect(Collectors.toSet());
    }

    /**
     * Returns the names of the attributes which are not included in the object class's schema. The object class's
     * Schema consists of the "must" and "may" attributes of the object class and the super classes to the object class.
     *
     * @param attributes A map of non-repeating attributes where one entry is "objectClass" with a valid assignment
     * @return the attribute names that are invalid for the given objectClass (and its super classes).
     * @throws RuntimeException If a Naming Exception is encountered when querying the schema class definition. This
     *                          can happen if the objectClass assignment is invalid.
     */
    public Set<String> getInvalidAttributeNames(Map<String, Collection<String>> attributes) throws RuntimeException {
        if (!attributes.keySet().stream().map(String::toLowerCase).collect(Collectors.toSet()).contains("objectclass")) {
            throw new RuntimeException(String.format("Cannot call \"%s\" without an \"objectClass\" attribute.",
                    this.getClass().getEnclosingMethod().getName()));
        }
        Set<String> permittedValues = getBasicAttributeValues(true, (Set<String>) attributes.get("objectClass"), "must", "may");
        return attributes
                .keySet()
                .stream()
                .filter(attributeName -> !permittedValues.contains(attributeName))
                .collect(Collectors.toSet());
    }
}
