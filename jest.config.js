module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  rootDir: ".",
  roots: ["<rootDir>/src/", "<rootDir>/tests/"],
  testMatch: ["**/?(*.)+(spec|test|tests).+(ts|tsx|js)"],
  transform: {
    "^.+\\.(ts|tsx)?$": "ts-jest",
  },
  moduleFileExtensions: ["ts", "tsx", "js", "json"],
  collectCoverage: true,
  reporters: ["default", ["jest-junit", { outputDirectory: "./coverage" }]],
  coverageDirectory: "./coverage/",
  collectCoverageFrom: [
    "src/**/*.{ts,tsx}",
    "!src/**/*.d.ts",
    "!**/node_modules/**",
  ],
  coverageReporters: ["text", "lcov", "json", "clover", "cobertura"],
};
