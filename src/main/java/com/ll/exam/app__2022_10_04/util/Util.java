package com.ll.exam.app__2022_10_04.util;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ll.exam.app__2022_10_04.app.AppConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.LinkedHashMap;
import java.util.Map;

@RequiredArgsConstructor
public class Util {
    private static ObjectMapper getObjectMapper() {
        return (ObjectMapper) AppConfig.getContext().getBean("objectMapper");
    }

    public static class json {

        public static Object toStr(Map<String, Object> map) {
            try {
                return getObjectMapper().writeValueAsString(map);
            } catch (JsonProcessingException e) {
                return null;
            }
        }

        public static Map<String, Object> toMap(String jsonStr) {
            try {
                return getObjectMapper().readValue(jsonStr, LinkedHashMap.class);
            } catch (JsonProcessingException e) {
                return null;
            }
        }
    }
}