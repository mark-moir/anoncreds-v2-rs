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
 * WarningUnsupportedFeature
 */
public class WarningUnsupportedFeature {
  /**
   * Gets or Sets tag
   */
  @JsonAdapter(TagEnum.Adapter.class)
  public enum TagEnum {
    UNSUPPORTED_FEATURE("UnsupportedFeature");

    private String value;

    TagEnum(String value) {
      this.value = value;
    }

    public String getValue() {
      return value;
    }

    @Override
    public String toString() {
      return String.valueOf(value);
    }

    public static TagEnum fromValue(String value) {
      for (TagEnum b : TagEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }

    public static class Adapter extends TypeAdapter<TagEnum> {
      @Override
      public void write(final JsonWriter jsonWriter, final TagEnum enumeration) throws IOException {
        jsonWriter.value(enumeration.getValue());
      }

      @Override
      public TagEnum read(final JsonReader jsonReader) throws IOException {
        String value =  jsonReader.nextString();
        return TagEnum.fromValue(value);
      }
    }

    public static void validateJsonElement(JsonElement jsonElement) throws IOException {
      String value = jsonElement.getAsString();
      TagEnum.fromValue(value);
    }
  }

  public static final String SERIALIZED_NAME_TAG = "tag";
  @SerializedName(SERIALIZED_NAME_TAG)
  @javax.annotation.Nonnull
  private TagEnum tag;

  public static final String SERIALIZED_NAME_CONTENTS = "contents";
  @SerializedName(SERIALIZED_NAME_CONTENTS)
  @javax.annotation.Nonnull
  private String contents;

  public WarningUnsupportedFeature() {
  }

  public WarningUnsupportedFeature tag(@javax.annotation.Nonnull TagEnum tag) {
    this.tag = tag;
    return this;
  }

  /**
   * Get tag
   * @return tag
   */
  @javax.annotation.Nonnull
  public TagEnum getTag() {
    return tag;
  }

  public void setTag(@javax.annotation.Nonnull TagEnum tag) {
    this.tag = tag;
  }


  public WarningUnsupportedFeature contents(@javax.annotation.Nonnull String contents) {
    this.contents = contents;
    return this;
  }

  /**
   * Get contents
   * @return contents
   */
  @javax.annotation.Nonnull
  public String getContents() {
    return contents;
  }

  public void setContents(@javax.annotation.Nonnull String contents) {
    this.contents = contents;
  }



  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    WarningUnsupportedFeature warningOneOf = (WarningUnsupportedFeature) o;
    return Objects.equals(this.tag, warningOneOf.tag) &&
        Objects.equals(this.contents, warningOneOf.contents);
  }

  @Override
  public int hashCode() {
    return Objects.hash(tag, contents);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class WarningUnsupportedFeature {\n");
    sb.append("    tag: ").append(toIndentedString(tag)).append("\n");
    sb.append("    contents: ").append(toIndentedString(contents)).append("\n");
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
    openapiFields.add("tag");
    openapiFields.add("contents");

    // a set of required properties/fields (JSON key names)
    openapiRequiredFields = new HashSet<String>();
    openapiRequiredFields.add("tag");
    openapiRequiredFields.add("contents");
  }

  /**
   * Validates the JSON Element and throws an exception if issues found
   *
   * @param jsonElement JSON Element
   * @throws IOException if the JSON Element is invalid with respect to WarningUnsupportedFeature
   */
  public static void validateJsonElement(JsonElement jsonElement) throws IOException {
      if (jsonElement == null) {
        if (!WarningUnsupportedFeature.openapiRequiredFields.isEmpty()) { // has required fields but JSON element is null
          throw new IllegalArgumentException(String.format("The required field(s) %s in WarningUnsupportedFeature is not found in the empty JSON string", WarningUnsupportedFeature.openapiRequiredFields.toString()));
        }
      }

      Set<Map.Entry<String, JsonElement>> entries = jsonElement.getAsJsonObject().entrySet();
      // check to see if the JSON string contains additional fields
      for (Map.Entry<String, JsonElement> entry : entries) {
        if (!WarningUnsupportedFeature.openapiFields.contains(entry.getKey())) {
          throw new IllegalArgumentException(String.format("The field `%s` in the JSON string is not defined in the `WarningUnsupportedFeature` properties. JSON: %s", entry.getKey(), jsonElement.toString()));
        }
      }

      // check to make sure all required properties/fields are present in the JSON string
      for (String requiredField : WarningUnsupportedFeature.openapiRequiredFields) {
        if (jsonElement.getAsJsonObject().get(requiredField) == null) {
          throw new IllegalArgumentException(String.format("The required field `%s` is not found in the JSON string: %s", requiredField, jsonElement.toString()));
        }
      }
        JsonObject jsonObj = jsonElement.getAsJsonObject();
      if (!jsonObj.get("tag").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `tag` to be a primitive type in the JSON string but got `%s`", jsonObj.get("tag").toString()));
      }
      // validate the required field `tag`
      TagEnum.validateJsonElement(jsonObj.get("tag"));
      if (!jsonObj.get("contents").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `contents` to be a primitive type in the JSON string but got `%s`", jsonObj.get("contents").toString()));
      }
  }

  public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
       if (!WarningUnsupportedFeature.class.isAssignableFrom(type.getRawType())) {
         return null; // this class only serializes 'WarningUnsupportedFeature' and its subtypes
       }
       final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
       final TypeAdapter<WarningUnsupportedFeature> thisAdapter
                        = gson.getDelegateAdapter(this, TypeToken.get(WarningUnsupportedFeature.class));

       return (TypeAdapter<T>) new TypeAdapter<WarningUnsupportedFeature>() {
           @Override
           public void write(JsonWriter out, WarningUnsupportedFeature value) throws IOException {
             JsonObject obj = thisAdapter.toJsonTree(value).getAsJsonObject();
             elementAdapter.write(out, obj);
           }

           @Override
           public WarningUnsupportedFeature read(JsonReader in) throws IOException {
             JsonElement jsonElement = elementAdapter.read(in);
             validateJsonElement(jsonElement);
             return thisAdapter.fromJsonTree(jsonElement);
           }

       }.nullSafe();
    }
  }

  /**
   * Create an instance of WarningUnsupportedFeature given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of WarningUnsupportedFeature
   * @throws IOException if the JSON string is invalid with respect to WarningUnsupportedFeature
   */
  public static WarningUnsupportedFeature fromJson(String jsonString) throws IOException {
    return JSON.getGson().fromJson(jsonString, WarningUnsupportedFeature.class);
  }

  /**
   * Convert an instance of WarningUnsupportedFeature to an JSON string
   *
   * @return JSON string
   */
  public String toJson() {
    return JSON.getGson().toJson(this);
  }
}

