# Use an official lightweight base image with tcpdump installed
FROM alpine:latest

# Install necessary packages
RUN apk add --no-cache tcpdump

# Copy your script to the container
COPY tcpdump.sh /usr/local/bin/tcpdump.sh

# Make the script executable
RUN chmod +x /usr/local/bin/tcpdump.sh

# Set the default command to run your script
CMD ["/usr/local/bin/tcpdump.sh"]
