*** Settings ***
Library    SeleniumLibrary
Resource    ../resources/codeblog.resource

Suite Teardown    Close Browser

*** Variables ***
${username}    timmy
${password}    timmy

*** Test Cases ***
Test Blog Post Visibility
    Open CodeBlog Application
    Login To CodeBlog    ${username}    ${password}
    Click Element    //*[contains(text(),"Introduction to SQL Joins")]
    Wait Until Page Contains    SQL joins combine rows