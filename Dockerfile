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

FROM golang:1.12

LABEL maintainer="XLAB d.o.o" \
      description="This image starts the core Emmy server\
       in CL mode (Camenisch-Lysyanskaya anonymous authentication scheme)"

WORKDIR /root

# Create appropriate directory structure
RUN mkdir -p emmy .emmy

# Copy config file
COPY config.yml .emmy/

# Run subsequent commands from the project root
WORKDIR /root/emmy
COPY ./ ./

# Install dependencies and compile the project
RUN go install

# Number of parameters for the CL scheme
ENV EMMY_CL_N_KNOWN=2 \
    EMMY_CL_N_COMMITTED=0 \
    EMMY_CL_N_HIDDEN=0

# Creates keys for the organization
RUN emmy generate cl

# Start emmy server
CMD emmy server cl

EXPOSE 7007
