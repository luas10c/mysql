/** @type{import('jest').Config} */
export default {
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
  testEnvironment: '<rootDir>/tests/environment.ts',
  transform: {
    '^.+\\.(t|j)sx?$': [
      '@swc/jest',
      {
        jsc: {
          baseUrl: './',
          parser: {
            syntax: 'typescript'
          },
          target: 'es2022',
          keepClassNames: true,
          paths: {
            '#/*': ['./src/*']
          }
        },
        module: {
          type: 'es6',
          strict: true,
          importInterop: 'swc'
        }
      }
    ]
  },
  moduleNameMapper: {
    '^#/(.*)$': '<rootDir>/src/$1'
  }
}
