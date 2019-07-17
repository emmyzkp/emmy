#
# Copyright 2017 XLAB d.o.o.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# First stage
FROM golang:1.12 as builder

# Run subsequent commands from the project root
WORKDIR /root/emmy/
COPY ./ ./

# Install dependencies and compile the project
# Disable dynamic linking to remove the dynamic libc dependency
RUN CGO_ENABLED=0 go install

# Second stage
FROM scratch

LABEL maintainer="XLAB d.o.o" \
      description="This image starts the core Emmy server\
       in CL mode (Camenisch-Lysyanskaya anonymous authentication scheme)"

EXPOSE 7007

# Number of parameters for the CL scheme
ENV EMMY_CL_N_KNOWN=2 \
    EMMY_CL_N_COMMITTED=0 \
    EMMY_CL_N_HIDDEN=0

# Copy config file
COPY config.yml /.emmy/config.yml

# Copy test dependencies
COPY ./anauth/test/testdata/ /anauth/test/testdata/

# Add the executable from the previous stage
COPY --from=builder /go/bin/emmy /emmy


# Creates keys for the organization
RUN ["/emmy", "generate", "cl"]

# Start emmy server
ENTRYPOINT ["/emmy", "server", "cl"]

