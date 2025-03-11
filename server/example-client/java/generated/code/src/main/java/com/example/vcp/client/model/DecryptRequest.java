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
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import java.io.IOException;
import java.util.Arrays;

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
 * Keys for decryption.
 */
public class DecryptRequest {
  public static final String SERIALIZED_NAME_AUTHORITY_SECRET_DATA = "authoritySecretData";
  @SerializedName(SERIALIZED_NAME_AUTHORITY_SECRET_DATA)
  @javax.annotation.Nonnull
  private String authoritySecretData;

  public static final String SERIALIZED_NAME_AUTHORITY_DECRYPTION_KEY = "authorityDecryptionKey";
  @SerializedName(SERIALIZED_NAME_AUTHORITY_DECRYPTION_KEY)
  @javax.annotation.Nonnull
  private String authorityDecryptionKey;

  public DecryptRequest() {
  }

  public DecryptRequest authoritySecretData(@javax.annotation.Nonnull String authoritySecretData) {
    this.authoritySecretData = authoritySecretData;
    return this;
  }

  /**
   * Authority secret data.
   * @return authoritySecretData
   */
  @javax.annotation.Nonnull
  public String getAuthoritySecretData() {
    return authoritySecretData;
  }

  public void setAuthoritySecretData(@javax.annotation.Nonnull String authoritySecretData) {
    this.authoritySecretData = authoritySecretData;
  }


  public DecryptRequest authorityDecryptionKey(@javax.annotation.Nonnull String authorityDecryptionKey) {
    this.authorityDecryptionKey = authorityDecryptionKey;
    return this;
  }

  /**
   * Authority decryption key.
   * @return authorityDecryptionKey
   */
  @javax.annotation.Nonnull
  public String getAuthorityDecryptionKey() {
    return authorityDecryptionKey;
  }

  public void setAuthorityDecryptionKey(@javax.annotation.Nonnull String authorityDecryptionKey) {
    this.authorityDecryptionKey = authorityDecryptionKey;
  }



  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    DecryptRequest decryptRequest = (DecryptRequest) o;
    return Objects.equals(this.authoritySecretData, decryptRequest.authoritySecretData) &&
        Objects.equals(this.authorityDecryptionKey, decryptRequest.authorityDecryptionKey);
  }

  @Override
  public int hashCode() {
    return Objects.hash(authoritySecretData, authorityDecryptionKey);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class DecryptRequest {\n");
    sb.append("    authoritySecretData: ").append(toIndentedString(authoritySecretData)).append("\n");
    sb.append("    authorityDecryptionKey: ").append(toIndentedString(authorityDecryptionKey)).append("\n");
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
    openapiFields.add("authoritySecretData");
    openapiFields.add("authorityDecryptionKey");

    // a set of required properties/fields (JSON key names)
    openapiRequiredFields = new HashSet<String>();
    openapiRequiredFields.add("authoritySecretData");
    openapiRequiredFields.add("authorityDecryptionKey");
  }

  /**
   * Validates the JSON Element and throws an exception if issues found
   *
   * @param jsonElement JSON Element
   * @throws IOException if the JSON Element is invalid with respect to DecryptRequest
   */
  public static void validateJsonElement(JsonElement jsonElement) throws IOException {
      if (jsonElement == null) {
        if (!DecryptRequest.openapiRequiredFields.isEmpty()) { // has required fields but JSON element is null
          throw new IllegalArgumentException(String.format("The required field(s) %s in DecryptRequest is not found in the empty JSON string", DecryptRequest.openapiRequiredFields.toString()));
        }
      }

      Set<Map.Entry<String, JsonElement>> entries = jsonElement.getAsJsonObject().entrySet();
      // check to see if the JSON string contains additional fields
      for (Map.Entry<String, JsonElement> entry : entries) {
        if (!DecryptRequest.openapiFields.contains(entry.getKey())) {
          throw new IllegalArgumentException(String.format("The field `%s` in the JSON string is not defined in the `DecryptRequest` properties. JSON: %s", entry.getKey(), jsonElement.toString()));
        }
      }

      // check to make sure all required properties/fields are present in the JSON string
      for (String requiredField : DecryptRequest.openapiRequiredFields) {
        if (jsonElement.getAsJsonObject().get(requiredField) == null) {
          throw new IllegalArgumentException(String.format("The required field `%s` is not found in the JSON string: %s", requiredField, jsonElement.toString()));
        }
      }
        JsonObject jsonObj = jsonElement.getAsJsonObject();
      if (!jsonObj.get("authoritySecretData").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `authoritySecretData` to be a primitive type in the JSON string but got `%s`", jsonObj.get("authoritySecretData").toString()));
      }
      if (!jsonObj.get("authorityDecryptionKey").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `authorityDecryptionKey` to be a primitive type in the JSON string but got `%s`", jsonObj.get("authorityDecryptionKey").toString()));
      }
  }

  public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
       if (!DecryptRequest.class.isAssignableFrom(type.getRawType())) {
         return null; // this class only serializes 'DecryptRequest' and its subtypes
       }
       final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
       final TypeAdapter<DecryptRequest> thisAdapter
                        = gson.getDelegateAdapter(this, TypeToken.get(DecryptRequest.class));

       return (TypeAdapter<T>) new TypeAdapter<DecryptRequest>() {
           @Override
           public void write(JsonWriter out, DecryptRequest value) throws IOException {
             JsonObject obj = thisAdapter.toJsonTree(value).getAsJsonObject();
             elementAdapter.write(out, obj);
           }

           @Override
           public DecryptRequest read(JsonReader in) throws IOException {
             JsonElement jsonElement = elementAdapter.read(in);
             validateJsonElement(jsonElement);
             return thisAdapter.fromJsonTree(jsonElement);
           }

       }.nullSafe();
    }
  }

  /**
   * Create an instance of DecryptRequest given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of DecryptRequest
   * @throws IOException if the JSON string is invalid with respect to DecryptRequest
   */
  public static DecryptRequest fromJson(String jsonString) throws IOException {
    return JSON.getGson().fromJson(jsonString, DecryptRequest.class);
  }

  /**
   * Convert an instance of DecryptRequest to an JSON string
   *
   * @return JSON string
   */
  public String toJson() {
    return JSON.getGson().toJson(this);
  }
}

