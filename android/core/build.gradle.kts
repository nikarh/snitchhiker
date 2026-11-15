import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// The protocol's messages (generated from proto/, the source of truth) and the app's model of a node, in plain
// Kotlin: tested on the JVM.
plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.wire)
    alias(libs.plugins.android.lint)
}

lint {
    warningsAsErrors = true
    abortOnError = true
    disable += setOf("GradleDependency", "NewerVersionAvailable")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_17
        allWarningsAsErrors = true
        // Wire generates `!!` on non-null lists for repeated scalar fields.
        freeCompilerArgs.add("-Xwarning-level=UNNECESSARY_NOT_NULL_ASSERTION:disabled")
        // A field named `other` (LintFinding.other) is equals()'s parameter in Wire's generated code.
        freeCompilerArgs.add("-Xwarning-level=PARAMETER_NAME_CHANGED_ON_OVERRIDE:disabled")
    }
}

wire {
    sourcePath {
        srcDir(rootProject.file("../proto"))
    }
    kotlin {}
}

dependencies {
    api(libs.wire.runtime)
    api(libs.coroutines.core)
    testImplementation(libs.junit)
    testImplementation(libs.coroutines.test)
}

tasks.test {
    testLogging {
        events("failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}
