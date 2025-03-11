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
import com.example.vcp.client.model.DataValue;
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.TypeAdapterFactory;
import com.google.gson.reflect.TypeToken;
import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import java.io.IOException;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.example.vcp.client.JSON;

/**
 * A Signature and other related data, including attribute values signed and witnesses for accumlators.
 */
public class SignatureAndRelatedData {
  public static final String SERIALIZED_NAME_SIGNATURE = "signature";
  @SerializedName(SERIALIZED_NAME_SIGNATURE)
  @javax.annotation.Nonnull
  private String signature;

  public static final String SERIALIZED_NAME_VALUES = "values";
  @SerializedName(SERIALIZED_NAME_VALUES)
  @javax.annotation.Nonnull
  private List<DataValue> values = new ArrayList<>();

  public static final String SERIALIZED_NAME_ACCUMULATOR_WITNESSES = "accumulatorWitnesses";
  @SerializedName(SERIALIZED_NAME_ACCUMULATOR_WITNESSES)
  @javax.annotation.Nonnull
  private Map<String, String> accumulatorWitnesses = new HashMap<>();

  public SignatureAndRelatedData() {
  }

  public SignatureAndRelatedData signature(@javax.annotation.Nonnull String signature) {
    this.signature = signature;
    return this;
  }

  /**
   * The signature from a Signer signing data values.
   * @return signature
   */
  @javax.annotation.Nonnull
  public String getSignature() {
    return signature;
  }

  public void setSignature(@javax.annotation.Nonnull String signature) {
    this.signature = signature;
  }


  public SignatureAndRelatedData values(@javax.annotation.Nonnull List<DataValue> values) {
    this.values = values;
    return this;
  }

  public SignatureAndRelatedData addValuesItem(DataValue valuesItem) {
    if (this.values == null) {
      this.values = new ArrayList<>();
    }
    this.values.add(valuesItem);
    return this;
  }

  /**
   * The data values used to produce the signature.
   * @return values
   */
  @javax.annotation.Nonnull
  public List<DataValue> getValues() {
    return values;
  }

  public void setValues(@javax.annotation.Nonnull List<DataValue> values) {
    this.values = values;
  }


  public SignatureAndRelatedData accumulatorWitnesses(@javax.annotation.Nonnull Map<String, String> accumulatorWitnesses) {
    this.accumulatorWitnesses = accumulatorWitnesses;
    return this;
  }

  public SignatureAndRelatedData putAccumulatorWitnessesItem(String key, String accumulatorWitnessesItem) {
    if (this.accumulatorWitnesses == null) {
      this.accumulatorWitnesses = new HashMap<>();
    }
    this.accumulatorWitnesses.put(key, accumulatorWitnessesItem);
    return this;
  }

  /**
   * Accumulator witnesses.
   * @return accumulatorWitnesses
   */
  @javax.annotation.Nonnull
  public Map<String, String> getAccumulatorWitnesses() {
    return accumulatorWitnesses;
  }

  public void setAccumulatorWitnesses(@javax.annotation.Nonnull Map<String, String> accumulatorWitnesses) {
    this.accumulatorWitnesses = accumulatorWitnesses;
  }



  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    SignatureAndRelatedData signatureAndRelatedData = (SignatureAndRelatedData) o;
    return Objects.equals(this.signature, signatureAndRelatedData.signature) &&
        Objects.equals(this.values, signatureAndRelatedData.values) &&
        Objects.equals(this.accumulatorWitnesses, signatureAndRelatedData.accumulatorWitnesses);
  }

  @Override
  public int hashCode() {
    return Objects.hash(signature, values, accumulatorWitnesses);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class SignatureAndRelatedData {\n");
    sb.append("    signature: ").append(toIndentedString(signature)).append("\n");
    sb.append("    values: ").append(toIndentedString(values)).append("\n");
    sb.append("    accumulatorWitnesses: ").append(toIndentedString(accumulatorWitnesses)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }


  public static HashSet<String> openapiFields;
  public static HashSet<String> openapiRequiredFields;

  static {
    // a set of all properties/fields (JSON key names)
    openapiFields = new HashSet<String>();
    openapiFields.add("signature");
    openapiFields.add("values");
    openapiFields.add("accumulatorWitnesses");

    // a set of required properties/fields (JSON key names)
    openapiRequiredFields = new HashSet<String>();
    openapiRequiredFields.add("signature");
    openapiRequiredFields.add("values");
    openapiRequiredFields.add("accumulatorWitnesses");
  }

  /**
   * Validates the JSON Element and throws an exception if issues found
   *
   * @param jsonElement JSON Element
   * @throws IOException if the JSON Element is invalid with respect to SignatureAndRelatedData
   */
  public static void validateJsonElement(JsonElement jsonElement) throws IOException {
      if (jsonElement == null) {
        if (!SignatureAndRelatedData.openapiRequiredFields.isEmpty()) { // has required fields but JSON element is null
          throw new IllegalArgumentException(String.format("The required field(s) %s in SignatureAndRelatedData is not found in the empty JSON string", SignatureAndRelatedData.openapiRequiredFields.toString()));
        }
      }

      Set<Map.Entry<String, JsonElement>> entries = jsonElement.getAsJsonObject().entrySet();
      // check to see if the JSON string contains additional fields
      for (Map.Entry<String, JsonElement> entry : entries) {
        if (!SignatureAndRelatedData.openapiFields.contains(entry.getKey())) {
          throw new IllegalArgumentException(String.format("The field `%s` in the JSON string is not defined in the `SignatureAndRelatedData` properties. JSON: %s", entry.getKey(), jsonElement.toString()));
        }
      }

      // check to make sure all required properties/fields are present in the JSON string
      for (String requiredField : SignatureAndRelatedData.openapiRequiredFields) {
        if (jsonElement.getAsJsonObject().get(requiredField) == null) {
          throw new IllegalArgumentException(String.format("The required field `%s` is not found in the JSON string: %s", requiredField, jsonElement.toString()));
        }
      }
        JsonObject jsonObj = jsonElement.getAsJsonObject();
      if (!jsonObj.get("signature").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `signature` to be a primitive type in the JSON string but got `%s`", jsonObj.get("signature").toString()));
      }
      // ensure the json data is an array
      if (!jsonObj.get("values").isJsonArray()) {
        throw new IllegalArgumentException(String.format("Expected the field `values` to be an array in the JSON string but got `%s`", jsonObj.get("values").toString()));
      }

      JsonArray jsonArrayvalues = jsonObj.getAsJsonArray("values");
      // validate the required field `values` (array)
      for (int i = 0; i < jsonArrayvalues.size(); i++) {
        DataValue.validateJsonElement(jsonArrayvalues.get(i));
      };
  }

  public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
       if (!SignatureAndRelatedData.class.isAssignableFrom(type.getRawType())) {
         return null; // this class only serializes 'SignatureAndRelatedData' and its subtypes
       }
       final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
       final TypeAdapter<SignatureAndRelatedData> thisAdapter
                        = gson.getDelegateAdapter(this, TypeToken.get(SignatureAndRelatedData.class));

       return (TypeAdapter<T>) new TypeAdapter<SignatureAndRelatedData>() {
           @Override
           public void write(JsonWriter out, SignatureAndRelatedData value) throws IOException {
             JsonObject obj = thisAdapter.toJsonTree(value).getAsJsonObject();
             elementAdapter.write(out, obj);
           }

           @Override
           public SignatureAndRelatedData read(JsonReader in) throws IOException {
             JsonElement jsonElement = elementAdapter.read(in);
             validateJsonElement(jsonElement);
             return thisAdapter.fromJsonTree(jsonElement);
           }

       }.nullSafe();
    }
  }

  /**
   * Create an instance of SignatureAndRelatedData given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of SignatureAndRelatedData
   * @throws IOException if the JSON string is invalid with respect to SignatureAndRelatedData
   */
  public static SignatureAndRelatedData fromJson(String jsonString) throws IOException {
    return JSON.getGson().fromJson(jsonString, SignatureAndRelatedData.class);
  }

  /**
   * Convert an instance of SignatureAndRelatedData to an JSON string
   *
   * @return JSON string
   */
  public String toJson() {
    return JSON.getGson().toJson(this);
  }
}

