---
layout: inner
title: Getting Started with SCAR
permalink: /installation/
---

## Installation

1. Clone the GitHub repository:

<pre><code>
git clone https://github.com/grycap/scar.git
</code></pre>

2. Install the required dependencies:

* [AWS SDK for Python (Boto 3)](https://github.com/boto/boto3) (v1.4.4+ is required)
* [Tabulate](https://pypi.python.org/pypi/tabulate)

You can automatically install the dependencies by issuing the following command:
{% highlight javascript %}
sudo pip install -r requirements.txt
{% endhighlight %}

3. (Optional) Define an alias for increased usability:
{% highlight javascript %}
cd scar
alias scar=`pwd`/scar.py
{% endhighlight %}

## Configuration

You need:

* Valid AWS [IAM](https://aws.amazon.com/iam/) user credentials (Access Key and Secret Key ID) with permissions to deploy Lambda functions.

* An IAM Role for the Lambda function to be authorized to access other AWS services during its execution.

### IAM User Credentials

 The credentials have to be configured in your <code>$HOME/.aws/credentials</code> file (as when using [AWS CLI](https://aws.amazon.com/cli/)). Check the AWS CLI documentation, specially section ["Configuration and Credential Files"](http://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html).

### IAM Role

The Lambda functions require an [IAM Role](http://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html) in order to acquire the required permissions to access the different AWS services during its execution.

There is a sample policy in the [lambda-execute-role.json](docs/aws/lambda-execute-role.json) file. This IAM Role should be created beforehand. There is further documentation on this topic in the ["Creating IAM roles"](http://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create.html) section of the AWS documentation.

### Configuration file

Create the file <code>~/.scar/scar.cfg</code> with the following structure (sample values are included, please customize it to your environment):

{% highlight javascript %}
[scar]
lambda_description = SCAR Lambda function
lambda_memory = 256
lambda_time = 200
lambda_region = us-east-1
lambda_role = arn:aws:iam::974349055189:role/lambda-s3-execution-role
lambda_timeout_threshold = 10
{% endhighlight %}

The values represent:

* lambda_description: Default description of the AWS Lambda function (can be customized with the <code>-d</code> parameter in <code>scar init</code>)
* lambda_memory: Default maximum memory allocated to the AWS Lambda function (can be customized with the <code>-m</code> parameter in <code>scar init</code>)
* lambda_time: Default maximum execution time of the AWS Lambda function (can be customized with the <code>-t</code> parameter in <code>scar init</code>).
* lambda_region: The [AWS region](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html) on which the AWS Lambda function will be created
* lambda_role: The [ARN](http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html) of the IAM Role that you just created in the previous section
* lambda_timeout_threshold: Default time used to postprocess the container output. Also used to avoid getting timeout error in case the execution of the container takes more time than the lambda_time (can be customized with the <code>-tt</code> parameter in <code>scar init</code>).

## Basic Usage

1. Create a Lambda function to execute a container (out of a Docker image that is stored in Docker Hub).

In these examples the [grycap/cowsay](https://hub.docker.com/r/grycap/cowsay/) Docker image in Docker Hub will be employed:

{% highlight javascript %}
scar init -n lambda-docker-cowsay -m 128 -t 300 grycap/cowsay
{% endhighlight %}

Notice that the memory and time limits for the Lambda function can be specified in the command-line. Upon first execution, the file <code>$HOME/.scar/scar.cfg</code> is created with default values for the memory and timeout, among other features. The command-line values always take precedence over the values in the configuration file. The default values are 128 MB for the memory (minimize memory) and 300 seconds for the timeout (maximize runtime).

Further information about the command-line arguments is available in the help:

{% highlight javascript %}
scar --help
{% endhighlight %}

2. Execute the Lambda function

{% highlight javascript %}
scar run lambda-docker-cowsay
{% endhighlight %}

The first invocation to the Lambda function will pull the Docker image from Docker Hub so it will take considerably longer than the subsequent invocations, which will most certainly reuse the existing Docker image, stored in <code>/tmp</code>.

3. Access the logs

The logs are stored in CloudWatch with a default retention policy of 30 days. The following command retrieves all the logs related to the Lambda function:

{% highlight javascript %}
scar log lambda-docker-cowsay
{% endhighlight %}

If you only want the logs related to a log-stream-name you can use:

{% highlight javascript %}
scar log lambda-docker-cowsay -ls 'log-stream-name'
{% endhighlight %}

And finally if you know the request id generated by your invocation, you can specify it if to get the logs related:

{% highlight javascript %}
scar log lambda-docker-cowsay -ri request-id
{% endhighlight %}

You can also specify the log stream name to retrieve the values related with the request id, usually this will be faster if the function has generated a lot of log output:

{% highlight javascript %}
scar log lambda-docker-cowsay -ls 'log-stream-name' -ri request-id
{% endhighlight %}

All values are shown in the output when executing <code>scar log</code>. Do not forget to use the single quotes, as indicated in the example, to avoid unwanted shell expansions.

4. Remove the Lambda function

You can remove the Lambda function together with the logs generated in CloudWatch by:

{% highlight javascript %}
scar rm -n lambda-docker-cowsay
{% endhighlight %}

## Advanced Usage

### Executing an user-defined shell-script

You can execute the Lambda function and specify a shell-script locally available in your machine to be executed within the container.

{% highlight javascript %}
scar run -s test/test-cowsay.sh lambda-docker-cowsay
{% endhighlight %}


The shell-script can be changed in each different execution of the Lambda function.

### Execute a shell-script upon invocation of the Lambda function

A shell-script can be specified when initializing the Lambda function to trigger its execution inside the container on each invocation of the Lambda function. For example:

{% highlight javascript %}
scar init -s test/test-env.sh -n lambda-test-init-script ubuntu:16.04
{% endhighlight %}

Now whenever this Lambda function is executed, the script will be run in the container:

{% highlight javascript %}
scar run lambda-test-init-script
{% endhighlight %}

This can be overridden by speciying a different shell-script when running the Lambda function.

### Passing Environment Variables

You can specify environment variables to the run command which will be in turn passed to the executed Docker container and made available to your shell-script:

{% highlight javascript %}
scar run -e TEST1=45 -e TEST2=69 -s test/test-global-vars.sh lambda-docker-cowsay
{% endhighlight %}

In particular, the following environment variables are automatically made available to the underlying Docker container:

* <code>AWS_ACCESS_KEY_ID</code>
* <code>AWS_SECRET_ACCESS_KEY</code>
* <code>AWS_SESSION_TOKEN</code>
* <code>AWS_SECURITY_TOKEN</code>

This allows a script running in the Docker container to access other AWS services. As an example, see how the AWS CLI is run on AWS Lambda in the [examples/aws-cli](examples/aws-cli) folder.

### Executing Applications

Applications available in the Docker image can be directly executed:

{% highlight javascript %}
 scar run lambda-docker-cowsay /usr/games/fortune
{% endhighlight %}

### Passing Arguments

You can also supply arguments which will be passed to the command executed in the Docker container:

{% highlight javascript %}
scar run lambda-docker-cowsay /usr/bin/perl /usr/games/cowsay Hello World
{% endhighlight %}

Note that since cowsay is a Perl script you will have to prepend it with the location of the Perl interpreter (in the Docker container).

### Obtaining a JSON Output

For easier scripting, a JSON output can be obtained by including the <code>--json</code> or the <code>-v</code> (even more verbose output) flags.

{% highlight javascript %}
scar run --json lambda-docker-cowsay
{% endhighlight %}

## Event-Driven File-Processing Programming Model<a id="programming-model"></a>

SCAR supports an event-driven programming model suitable for the execution of highly-parallel file-processing applications that require a customized runtime environment.

The following command:

{% highlight javascript %}
scar init -s user-defined-script.sh -n lambda-function-name -es bucket-name repo/image:latest
{% endhighlight %}

Creates a Lambda function to execute the shell-script <code>user-defined-script.sh</code> inside a Docker container created out of the <code>repo/image:latest</code> Docker image stored in Docker Hub.

The following workflow summarises the programming model, which heavily uses the [convention over configuration](https://en.wikipedia.org/wiki/Convention_over_configuration) pattern:

1. The Amazon S3 bucket <code>bucket-name</code> will be created if it does not exist, and the <code>input</code> and <code>output</code> folders inside.
1. The Lambda function is triggered upon uploading a file into the <code>input</code> folder of the <code>bucket-name</code> bucket.
1. The Lambda function retrieves the file from the Amazon S3 bucket and makes it available for the shell-script running inside the container in the <code>/tmp/$REQUEST_ID/input</code> folder. The <code>$SCAR_INPUT_FILE</code> environment variable will point to the location of the input file.
1. The shell-script processes the input file and produces the output (either one or multiple files) in the folder <code>/tmp/$REQUEST_ID/output</code>.
1. The output files are automatically uploaded by the Lambda function into the <code>output</code> folder of <code>bucket-name</code>.

Many instances of the Lambda function may run concurrently and independently, depending on the files to be processed in the S3 bucket. Initial executions of the Lambda may require retrieving the Docker image from Docker Hub but this will be cached for subsequent invocations, thus speeding up the execution process.

For further information, examples of such application are included in the [examples/ffmpeg](examples/ffmpeg) folder, in order to run the [FFmpeg](https://ffmpeg.org/) video codification tool, and in the [examples/imagemagick](examples/imagemagick), in order to run the [ImageMagick](https://www.imagemagick.org) image manipulation tool, both on AWS Lambda.

## More Event-Driven File-Processing thingies

SCAR also supports another way of executing highly-parallel file-processing applications that require a customized runtime environment.

After creating a function with the command:


{% highlight javascript %}
scar init -s user-defined-script.sh -n lambda-function-name repo/image:latest
{% endhighlight %}

You can activate the SCAR event launcher using the <code>run</code> command like this:


{% highlight javascript %}
scar run -es bucket-name lambda-function-name
{% endhighlight %}

This command lists the files in the <code>input</code> folder of the specified bucket and sends the required events (one per file) to the lambda function.

The following workflow summarises the programming model, the differences with the main programming model are in bold:

1. **The folder <code>input</code> inside the amazon S3 bucket <code>bucket-name</code> will be searched for files.**
1. **The Lambda function is triggered once for each file found in the <code>input</code> folder. The first execution is of type <code>request-response</code> and the rest are <code>asynchronous</code>(this is done to ensure the caching and accelerate the execution).**
1. The Lambda function retrieves the file from the Amazon S3 bucket and makes it available for the shell-script running inside the container in the <code>/tmp/$REQUEST_ID/input</code> folder. The <code>$SCAR_INPUT_FILE</code> environment variable will point to the location of the input file.
1. The shell-script processes the input file and produces the output (either one or multiple files) in the folder <code>/tmp/$REQUEST_ID/output</code>.
1. The output files are automatically uploaded by the Lambda function into the <code>output</code> folder of <code>bucket-name</code>.

## Local Testing of the Docker images via udocker

You can test locally if the Docker image will be able to run in AWS Lambda by means of udocker (available in the <code>lambda</code> directory) and taking into account the following limitations:

* udocker cannot run on macOS. Use a Linux box instead.
* Images based in Alpine will not work.

 Procedure for testing:

0. (Optional) Define an alias for easier usage

{% highlight javascript %}
alias udocker=`pwd`/lambda/udocker
{% endhighlight %}

1. Pull the image from Docker Hub into udocker

{% highlight javascript %}
udocker pull grycap/cowsay
{% endhighlight %}

2. Create the container

{% highlight javascript %}
udocker create --name=my-container grycap/cowsay
{% endhighlight %}

3. Change the execution mode to Fakechroot

{% highlight javascript %}
udocker setup --execmode=F1 my-container
{% endhighlight %}

4. Execute the container

{% highlight javascript %}
udocker run my-container
{% endhighlight %}

5. (Optional) Get a shell into the container

{% highlight javascript %}
udocker run my-container /bin/sh
{% endhighlight %}

Further information is available in the udocker documentation:

{% highlight javascript %}
udocker help
{% endhighlight %}

## Local Testing of the Lambda functions with emulambda

For easier debugging of the Lambda functions, [emulambda](https://github.com/fugue/emulambda) can be employed to locally execute them.

1. Install emulambda

2. Execute a sample local test

{% highlight javascript %}
sh test/emulambda/run-local-test.sh
{% endhighlight %}

This test locally executes the ubuntu:16.04 image in DockerHub via udocker executing a simple shell-script.

## Licensing

SCAR is licensed under the Apache License, Version 2.0. See
[LICENSE](https://github.com/grycap/scar/blob/master/LICENSE) for the full
license text.

