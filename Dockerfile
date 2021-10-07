FROM ruby:3
ARG omejdn_version="unknown"

WORKDIR /opt

#Rebuild if Gemfile changed
COPY Gemfile .
COPY Gemfile.lock .
RUN bundle install
RUN echo $omejdn_version > .version

COPY . .

EXPOSE 4567

CMD [ "ruby", "omejdn.rb" ]
