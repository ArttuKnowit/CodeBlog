FROM python:3.12-slim

# Install system deps: curl, chromium, xauth, and Playwright browser deps
RUN apt-get update && apt-get install -y \
    curl chromium xauth \
    libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 \
    libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 \
    libasound2 libatspi2.0-0 libwayland-client0 libwayland-egl1 \
    libwayland-server0 fonts-unifont fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps
ADD requirements.txt /
RUN pip3 install --no-cache-dir -r requirements.txt

# Install Node.js
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# Init RF Browser (installs Playwright itself)
RUN rfbrowser init

# Copy test files
COPY ./tests /home/test_user/robot_tests/tests
COPY ./resources /home/test_user/robot_tests/resources

WORKDIR /home/test_user/robot_tests

CMD ["robot", "-v", "URL:http://codeblog_app:5000", "--outputdir", "results/", "--loglevel", "DEBUG", "-e", "not_ready", "tests/"]
