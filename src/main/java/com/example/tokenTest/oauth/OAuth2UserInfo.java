package com.example.tokenTest.oauth;

import java.util.Map;

public interface OAuth2UserInfo {
    Map<String, Object> getAttributes();
    String getId();
    String getNickname();
    String getEmail();
    String getImageUrl();
}
