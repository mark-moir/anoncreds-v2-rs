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
import com.example.vcp.client.model.DVInt;
import com.example.vcp.client.model.DVText;
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import java.io.IOException;
import java.util.Arrays;



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

public class DataValue extends AbstractOpenApiSchema {
    private static final Logger log = Logger.getLogger(DataValue.class.getName());

    public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
        @SuppressWarnings("unchecked")
        @Override
        public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
            if (!DataValue.class.isAssignableFrom(type.getRawType())) {
                return null; // this class only serializes 'DataValue' and its subtypes
            }
            final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
            final TypeAdapter<DVInt> adapterDVInt = gson.getDelegateAdapter(this, TypeToken.get(DVInt.class));
            final TypeAdapter<DVText> adapterDVText = gson.getDelegateAdapter(this, TypeToken.get(DVText.class));

            return (TypeAdapter<T>) new TypeAdapter<DataValue>() {
                @Override
                public void write(JsonWriter out, DataValue value) throws IOException {
                    if (value == null || value.getActualInstance() == null) {
                        elementAdapter.write(out, null);
                        return;
                    }

                    // check if the actual instance is of the type `DVInt`
                    if (value.getActualInstance() instanceof DVInt) {
                        JsonElement element = adapterDVInt.toJsonTree((DVInt)value.getActualInstance());
                        elementAdapter.write(out, element);
                        return;
                    }
                    // check if the actual instance is of the type `DVText`
                    if (value.getActualInstance() instanceof DVText) {
                        JsonElement element = adapterDVText.toJsonTree((DVText)value.getActualInstance());
                        elementAdapter.write(out, element);
                        return;
                    }
                    throw new IOException("Failed to serialize as the type doesn't match oneOf schemas: DVInt, DVText");
                }

                @Override
                public DataValue read(JsonReader in) throws IOException {
                    Object deserialized = null;
                    JsonElement jsonElement = elementAdapter.read(in);

                    int match = 0;
                    ArrayList<String> errorMessages = new ArrayList<>();
                    TypeAdapter actualAdapter = elementAdapter;

                    // deserialize DVInt
                    try {
                        // validate the JSON object to see if any exception is thrown
                        DVInt.validateJsonElement(jsonElement);
                        actualAdapter = adapterDVInt;
                        match++;
                        log.log(Level.FINER, "Input data matches schema 'DVInt'");
                    } catch (Exception e) {
                        // deserialization failed, continue
                        errorMessages.add(String.format("Deserialization for DVInt failed with `%s`.", e.getMessage()));
                        log.log(Level.FINER, "Input data does not match schema 'DVInt'", e);
                    }
                    // deserialize DVText
                    try {
                        // validate the JSON object to see if any exception is thrown
                        DVText.validateJsonElement(jsonElement);
                        actualAdapter = adapterDVText;
                        match++;
                        log.log(Level.FINER, "Input data matches schema 'DVText'");
                    } catch (Exception e) {
                        // deserialization failed, continue
                        errorMessages.add(String.format("Deserialization for DVText failed with `%s`.", e.getMessage()));
                        log.log(Level.FINER, "Input data does not match schema 'DVText'", e);
                    }

                    if (match == 1) {
                        DataValue ret = new DataValue();
                        ret.setActualInstance(actualAdapter.fromJsonTree(jsonElement));
                        return ret;
                    }

                    throw new IOException(String.format("Failed deserialization for DataValue: %d classes match result, expected 1. Detailed failure message for oneOf schemas: %s. JSON: %s", match, errorMessages, jsonElement.toString()));
                }
            }.nullSafe();
        }
    }

    // store a list of schema names defined in oneOf
    public static final Map<String, Class<?>> schemas = new HashMap<String, Class<?>>();

    public DataValue() {
        super("oneOf", Boolean.FALSE);
    }

    public DataValue(Object o) {
        super("oneOf", Boolean.FALSE);
        setActualInstance(o);
    }

    static {
        schemas.put("DVInt", DVInt.class);
        schemas.put("DVText", DVText.class);
    }

    @Override
    public Map<String, Class<?>> getSchemas() {
        return DataValue.schemas;
    }

    /**
     * Set the instance that matches the oneOf child schema, check
     * the instance parameter is valid against the oneOf child schemas:
     * DVInt, DVText
     *
     * It could be an instance of the 'oneOf' schemas.
     */
    @Override
    public void setActualInstance(Object instance) {
        if (instance instanceof DVInt) {
            super.setActualInstance(instance);
            return;
        }

        if (instance instanceof DVText) {
            super.setActualInstance(instance);
            return;
        }

        throw new RuntimeException("Invalid instance type. Must be DVInt, DVText");
    }

    /**
     * Get the actual instance, which can be the following:
     * DVInt, DVText
     *
     * @return The actual instance (DVInt, DVText)
     */
    @SuppressWarnings("unchecked")
    @Override
    public Object getActualInstance() {
        return super.getActualInstance();
    }

    /**
     * Get the actual instance of `DVInt`. If the actual instance is not `DVInt`,
     * the ClassCastException will be thrown.
     *
     * @return The actual instance of `DVInt`
     * @throws ClassCastException if the instance is not `DVInt`
     */
    public DVInt getDVInt() throws ClassCastException {
        return (DVInt)super.getActualInstance();
    }

    /**
     * Get the actual instance of `DVText`. If the actual instance is not `DVText`,
     * the ClassCastException will be thrown.
     *
     * @return The actual instance of `DVText`
     * @throws ClassCastException if the instance is not `DVText`
     */
    public DVText getDVText() throws ClassCastException {
        return (DVText)super.getActualInstance();
    }

    /**
     * Validates the JSON Element and throws an exception if issues found
     *
     * @param jsonElement JSON Element
     * @throws IOException if the JSON Element is invalid with respect to DataValue
     */
    public static void validateJsonElement(JsonElement jsonElement) throws IOException {
        // validate oneOf schemas one by one
        int validCount = 0;
        ArrayList<String> errorMessages = new ArrayList<>();
        // validate the json string with DVInt
        try {
            DVInt.validateJsonElement(jsonElement);
            validCount++;
        } catch (Exception e) {
            errorMessages.add(String.format("Deserialization for DVInt failed with `%s`.", e.getMessage()));
            // continue to the next one
        }
        // validate the json string with DVText
        try {
            DVText.validateJsonElement(jsonElement);
            validCount++;
        } catch (Exception e) {
            errorMessages.add(String.format("Deserialization for DVText failed with `%s`.", e.getMessage()));
            // continue to the next one
        }
        if (validCount != 1) {
            throw new IOException(String.format("The JSON string is invalid for DataValue with oneOf schemas: DVInt, DVText. %d class(es) match the result, expected 1. Detailed failure message for oneOf schemas: %s. JSON: %s", validCount, errorMessages, jsonElement.toString()));
        }
    }

    /**
     * Create an instance of DataValue given an JSON string
     *
     * @param jsonString JSON string
     * @return An instance of DataValue
     * @throws IOException if the JSON string is invalid with respect to DataValue
     */
    public static DataValue fromJson(String jsonString) throws IOException {
        return JSON.getGson().fromJson(jsonString, DataValue.class);
    }

    /**
     * Convert an instance of DataValue to an JSON string
     *
     * @return JSON string
     */
    public String toJson() {
        return JSON.getGson().toJson(this);
    }
}

