/*
 * vcp_server
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.example.vcp.client.model;

import java.util.Objects;
import com.example.vcp.client.model.WarningUnsupportedFeature;
import com.example.vcp.client.model.WarningRevealPrivacy;
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;



import java.io.IOException;
import java.lang.reflect.Type;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParseException;
import com.google.gson.TypeAdapter;
import com.google.gson.TypeAdapterFactory;
import com.google.gson.reflect.TypeToken;
import com.google.gson.JsonPrimitive;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;
import com.google.gson.JsonParseException;

import com.example.vcp.client.JSON;

public class Warning extends AbstractOpenApiSchema {
    private static final Logger log = Logger.getLogger(Warning.class.getName());

    public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
        @SuppressWarnings("unchecked")
        @Override
        public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
            if (!Warning.class.isAssignableFrom(type.getRawType())) {
                return null; // this class only serializes 'Warning' and its subtypes
            }
            final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
            final TypeAdapter<WarningUnsupportedFeature> adapterWarningUnsupportedFeature = gson.getDelegateAdapter(this, TypeToken.get(WarningUnsupportedFeature.class));
            final TypeAdapter<WarningRevealPrivacy> adapterWarningRevealPrivacy = gson.getDelegateAdapter(this, TypeToken.get(WarningRevealPrivacy.class));

            return (TypeAdapter<T>) new TypeAdapter<Warning>() {
                @Override
                public void write(JsonWriter out, Warning value) throws IOException {
                    if (value == null || value.getActualInstance() == null) {
                        elementAdapter.write(out, null);
                        return;
                    }

                    // check if the actual instance is of the type `WarningUnsupportedFeature`
                    if (value.getActualInstance() instanceof WarningUnsupportedFeature) {
                        JsonElement element = adapterWarningUnsupportedFeature.toJsonTree((WarningUnsupportedFeature)value.getActualInstance());
                        elementAdapter.write(out, element);
                        return;
                    }
                    // check if the actual instance is of the type `WarningRevealPrivacy`
                    if (value.getActualInstance() instanceof WarningRevealPrivacy) {
                        JsonElement element = adapterWarningRevealPrivacy.toJsonTree((WarningRevealPrivacy)value.getActualInstance());
                        elementAdapter.write(out, element);
                        return;
                    }
                    throw new IOException("Failed to serialize as the type doesn't match oneOf schemas: WarningUnsupportedFeature, WarningRevealPrivacy");
                }

                @Override
                public Warning read(JsonReader in) throws IOException {
                    Object deserialized = null;
                    JsonElement jsonElement = elementAdapter.read(in);

                    int match = 0;
                    ArrayList<String> errorMessages = new ArrayList<>();
                    TypeAdapter actualAdapter = elementAdapter;

                    // deserialize WarningUnsupportedFeature
                    try {
                        // validate the JSON object to see if any exception is thrown
                        WarningUnsupportedFeature.validateJsonElement(jsonElement);
                        actualAdapter = adapterWarningUnsupportedFeature;
                        match++;
                        log.log(Level.FINER, "Input data matches schema 'WarningUnsupportedFeature'");
                    } catch (Exception e) {
                        // deserialization failed, continue
                        errorMessages.add(String.format("Deserialization for WarningUnsupportedFeature failed with `%s`.", e.getMessage()));
                        log.log(Level.FINER, "Input data does not match schema 'WarningUnsupportedFeature'", e);
                    }
                    // deserialize WarningRevealPrivacy
                    try {
                        // validate the JSON object to see if any exception is thrown
                        WarningRevealPrivacy.validateJsonElement(jsonElement);
                        actualAdapter = adapterWarningRevealPrivacy;
                        match++;
                        log.log(Level.FINER, "Input data matches schema 'WarningRevealPrivacy'");
                    } catch (Exception e) {
                        // deserialization failed, continue
                        errorMessages.add(String.format("Deserialization for WarningRevealPrivacy failed with `%s`.", e.getMessage()));
                        log.log(Level.FINER, "Input data does not match schema 'WarningRevealPrivacy'", e);
                    }

                    if (match == 1) {
                        Warning ret = new Warning();
                        ret.setActualInstance(actualAdapter.fromJsonTree(jsonElement));
                        return ret;
                    }

                    throw new IOException(String.format("Failed deserialization for Warning: %d classes match result, expected 1. Detailed failure message for oneOf schemas: %s. JSON: %s", match, errorMessages, jsonElement.toString()));
                }
            }.nullSafe();
        }
    }

    // store a list of schema names defined in oneOf
    public static final Map<String, Class<?>> schemas = new HashMap<String, Class<?>>();

    public Warning() {
        super("oneOf", Boolean.FALSE);
    }

    public Warning(Object o) {
        super("oneOf", Boolean.FALSE);
        setActualInstance(o);
    }

    static {
        schemas.put("WarningUnsupportedFeature", WarningUnsupportedFeature.class);
        schemas.put("WarningRevealPrivacy", WarningRevealPrivacy.class);
    }

    @Override
    public Map<String, Class<?>> getSchemas() {
        return Warning.schemas;
    }

    /**
     * Set the instance that matches the oneOf child schema, check
     * the instance parameter is valid against the oneOf child schemas:
     * WarningUnsupportedFeature, WarningRevealPrivacy
     *
     * It could be an instance of the 'oneOf' schemas.
     */
    @Override
    public void setActualInstance(Object instance) {
        if (instance instanceof WarningUnsupportedFeature) {
            super.setActualInstance(instance);
            return;
        }

        if (instance instanceof WarningRevealPrivacy) {
            super.setActualInstance(instance);
            return;
        }

        throw new RuntimeException("Invalid instance type. Must be WarningUnsupportedFeature, WarningRevealPrivacy");
    }

    /**
     * Get the actual instance, which can be the following:
     * WarningUnsupportedFeature, WarningRevealPrivacy
     *
     * @return The actual instance (WarningUnsupportedFeature, WarningRevealPrivacy)
     */
    @SuppressWarnings("unchecked")
    @Override
    public Object getActualInstance() {
        return super.getActualInstance();
    }

    /**
     * Get the actual instance of `WarningUnsupportedFeature`. If the actual instance is not `WarningUnsupportedFeature`,
     * the ClassCastException will be thrown.
     *
     * @return The actual instance of `WarningUnsupportedFeature`
     * @throws ClassCastException if the instance is not `WarningUnsupportedFeature`
     */
    public WarningUnsupportedFeature getWarningUnsupportedFeature() throws ClassCastException {
        return (WarningUnsupportedFeature)super.getActualInstance();
    }

    /**
     * Get the actual instance of `WarningRevealPrivacy`. If the actual instance is not `WarningRevealPrivacy`,
     * the ClassCastException will be thrown.
     *
     * @return The actual instance of `WarningRevealPrivacy`
     * @throws ClassCastException if the instance is not `WarningRevealPrivacy`
     */
    public WarningRevealPrivacy getWarningRevealPrivacy() throws ClassCastException {
        return (WarningRevealPrivacy)super.getActualInstance();
    }

    /**
     * Validates the JSON Element and throws an exception if issues found
     *
     * @param jsonElement JSON Element
     * @throws IOException if the JSON Element is invalid with respect to Warning
     */
    public static void validateJsonElement(JsonElement jsonElement) throws IOException {
        // validate oneOf schemas one by one
        int validCount = 0;
        ArrayList<String> errorMessages = new ArrayList<>();
        // validate the json string with WarningUnsupportedFeature
        try {
            WarningUnsupportedFeature.validateJsonElement(jsonElement);
            validCount++;
        } catch (Exception e) {
            errorMessages.add(String.format("Deserialization for WarningUnsupportedFeature failed with `%s`.", e.getMessage()));
            // continue to the next one
        }
        // validate the json string with WarningRevealPrivacy
        try {
            WarningRevealPrivacy.validateJsonElement(jsonElement);
            validCount++;
        } catch (Exception e) {
            errorMessages.add(String.format("Deserialization for WarningRevealPrivacy failed with `%s`.", e.getMessage()));
            // continue to the next one
        }
        if (validCount != 1) {
            throw new IOException(String.format("The JSON string is invalid for Warning with oneOf schemas: WarningUnsupportedFeature, WarningRevealPrivacy. %d class(es) match the result, expected 1. Detailed failure message for oneOf schemas: %s. JSON: %s", validCount, errorMessages, jsonElement.toString()));
        }
    }

    /**
     * Create an instance of Warning given an JSON string
     *
     * @param jsonString JSON string
     * @return An instance of Warning
     * @throws IOException if the JSON string is invalid with respect to Warning
     */
    public static Warning fromJson(String jsonString) throws IOException {
        return JSON.getGson().fromJson(jsonString, Warning.class);
    }

    /**
     * Convert an instance of Warning to an JSON string
     *
     * @return JSON string
     */
    public String toJson() {
        return JSON.getGson().toJson(this);
    }
}

