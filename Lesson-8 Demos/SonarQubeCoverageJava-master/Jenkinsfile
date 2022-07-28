node('master'){
	
	def mvnHome = tool 'MavenBuildTool'
	def sonarScannerHome = tool 'Scanner'
	
	try {
		stage('Checkout Code'){
			checkout scm
		}
		
		stage('Maven Build'){
			sh "${mvnHome}/bin/mvn clean install"
		}
		
		stage('Test Cases Execution'){
			sh "${mvnHome}/bin/mvn test"
		}
		
		stage('SonarQube Analysis'){
			/*withCredentials([string(credentialsId: 'SonarQubeToken', variable: 'SONARQUBE_TOKEN')]) {
				//sh "${sonarScannerHome}/bin/sonar-scanner -Dsonar.host.url=http://35.172.192.145:9000/ -Dsonar.login=${SONARQUBE_TOKEN} -Dsonar.projectKey=com.example:java-example-project"
			}*/
		}
		
		stage('Archive Artifacts'){
			archiveArtifacts artifacts: 'target/*.jar', followSymlinks: false
		}
	}
	catch (Exception e){
		currentBuild.result = 'FAILURE'
		echo currentBuild.currentResult
	}finally{
		emailext attachLog: true, attachmentsPattern: 'target/surefire-reports/*.xml', 
			 body: '''$PROJECT_NAME - Build # $BUILD_NUMBER - $BUILD_STATUS:
	Check console output at $BUILD_URL to view the results.''', 
			compressLog: true, recipientProviders: [buildUser(), requestor()], subject: '$PROJECT_NAME - Build # $BUILD_NUMBER - $BUILD_STATUS!', to: 'anuj_sharma401@yahoo.com'
	}
}
