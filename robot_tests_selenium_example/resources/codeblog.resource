*** Settings ***
Library    SeleniumLibrary

*** Variables ***
${URL}    http://127.0.0.1:5000 


*** Keywords ***
Open CodeBlog Application
    [Documentation]    This keyword opens the CodeBlog application
    ...
    ...    This keyword first opens a browser, then goes to ${URL}
    Open Browser    ${URL}    chrome
    # Open Browser    ${URL}    headlesschrome    # If you want to run tests headless
    Wait Until Page Contains Element    //body

Login To CodeBlog
    [Documentation]    This keyword assumes an open browser
    [Arguments]    ${username}    ${password}
    Go To    ${URL}/login
    Wait until Page Contains Element    id=username
    Input Text    id=username    ${username}
    Input Password    id=password    ${password}
    Click Button    Login
    Sleep    3