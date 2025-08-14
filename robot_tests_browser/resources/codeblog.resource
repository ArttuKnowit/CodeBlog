** Settings ***
Library    Browser

*** Variables ***
${URL}    http://127.0.0.1:5000

*** Keywords ***
Open CodeBlog
    New Browser    chromium
    New Page       ${URL}
    Wait For Elements State    //body
    Sleep    5