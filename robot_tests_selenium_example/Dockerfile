FROM python:3.12-slim

RUN apt-get -y update \
    && apt-get -y upgrade

# Install dependencies
RUN apt-get update && apt-get install -y \
    tzdata \
    wget \
    nano \ 
    xvfb \ 
    locales \
    && apt-get clean  
    #&& rm /etc/apt/sources.list.d/trusty-copies.list \
    #&& rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Install Firefox 
RUN apt-get -y update \
    && apt-get install -y firefox-esr 

# Install Chrome (Webdriver is intgrated in the debian package)
RUN apt-get -y update \
    && wget -N https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb -P ~/ \
    && apt install -y ~/google-chrome-stable_current_amd64.deb  \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

#set correct date
ENV TZ=Europe/Helsinki
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Set the locale
#RUN locale-gen en_US.UTF-8
#ENV LANG en_US.UTF-8
#ENV LANGUAGE en_US:en
#ENV LC_ALL en_US.UTF-8

RUN pip3 install --upgrade pip

#xvfb-run
ADD https://gist.github.com/roadsideseb/5a91271c07bb0de7bfa6/raw/d07b4eecf02fd3341ef72753e4c5875cf137bda8/xvfb-run.sh /usr/bin/xvfb-run
RUN chmod a+rx /usr/bin/xvfb-run
ADD requirements.txt /
RUN pip3 install -r requirements.txt

# Copy the test project files
COPY . /app

# Set the working directory
WORKDIR /app

# Create the results directory
RUN mkdir -p /app/results


CMD ["robot", "-v", "URL:http://127.0.0.1:5000", "--outputdir", "results/", "--loglevel", "DEBUG", "-e", "not_ready", "tests/"]

# Copy the result files to the host machine
VOLUME ["/results"]