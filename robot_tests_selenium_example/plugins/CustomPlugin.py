from robot.api.deco import keyword
from SeleniumLibrary.base import LibraryComponent

class Plugin(LibraryComponent):
    @keyword
    def open_browser(self, url, browser, *args, **kwargs):
        """This is an overwrite of Open Browser to make sure urls always
        begin with 'http://. Passes other arguments on as they are."""
        url = str(url)
        if not url.startswith('http://') or url.startswith('https://'):
            url = 'http://' + url
        elif url.startswith('https://'):
            url = url.replace('https://', 'http://')
        self.open_browser(url, browser, *args, **kwargs)