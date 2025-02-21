# Use an official OpenJDK runtime as the base image
FROM openjdk:11

# Set the working directory to /app
WORKDIR /app

# Copy the Spring Boot application JAR file into the container
COPY ./target/springboottest-0.0.1-SNAPSHOT.jarspringboottest-0.0.1-SNAPSHOT.jar

# Expose port 8080 for the application
EXPOSE 8080

# Define the command to run the Spring Boot application
CMD ["java", "-jar", "springboottest-0.0.1-SNAPSHOT.jar"]
