# Use an official lightweight base image with tcpdump installed
FROM alpine:latest

# Install necessary packages
RUN apk add --no-cache tcpdump

# Copy your script to the container
COPY cleanup.sh /usr/local/bin/cleanup.sh

# Make the script executable
RUN chmod +x /usr/local/bin/cleanup.sh

# Set the default command to run your script
CMD ["/usr/local/bin/cleanup.sh"]
