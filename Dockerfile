# Use a minimal JDK 21 image with Maven for building
FROM maven:3.9.6-eclipse-temurin-21 as builder

WORKDIR /app

# Copy pom.xml and download dependencies first (leverages Docker cache)
COPY pom.xml .
RUN mvn dependency:go-offline

# Copy the rest of the source code
COPY src ./src

# Package the Spring Boot app (skip tests if desired)
RUN mvn clean package -DskipTests

# -------------------------------

# Use lightweight JDK 21 image for running
FROM eclipse-temurin:21-jre

WORKDIR /app

# Copy the built jar from the builder stage
COPY --from=builder /app/target/*.jar app.jar

# Expose port 8080 (Spring Boot default)
EXPOSE 8080

# Run the jar file
ENTRYPOINT ["java", "-jar", "app.jar"]
