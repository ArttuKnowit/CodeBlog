from robot.api.deco import keyword
from robot.libraries.BuiltIn import BuiltIn
from SeleniumLibrary import SeleniumLibrary
from SeleniumLibrary.base import keyword
from SeleniumLibrary.keywords.element import ElementKeywords


class ExtendedSeleniumLibrary(SeleniumLibrary):
    @keyword
    def open_browser_maximized(self, url, brw='ff'):
        """This is a new keyword definition"""
        self.open_browser(url, brw)
        BuiltIn().log_to_console("Extended keyword used")
        self.maximize_browser_window()
        
    @keyword
    def click_link(self, locator, timeout=5):
        """This keyword rewrites an existing keyword"""
        self.wait_until_page_contains(locator, timeout=timeout)
        ElementKeywords(self).click_link(locator)