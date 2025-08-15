*** Settings ***
Library    RequestsLibrary
Resource    ../resources/codeblog.resource

*** Test Cases ***
Test Posts GET request
    ${response}    GET    ${URL}/api/posts
    Log To Console    ${response}