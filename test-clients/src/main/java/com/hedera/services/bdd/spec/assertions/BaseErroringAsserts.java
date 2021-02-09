package com.hedera.services.bdd.spec.assertions;

/*-
 * ‌
 * Hedera Services Test Clients
 * ​
 * Copyright (C) 2018 - 2021 Hedera Hashgraph, LLC
 * ​
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ‍
 */

import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class BaseErroringAsserts<T> implements ErroringAsserts<T> {
	private final List<Function<T, Optional<Throwable>>> tests;

	public BaseErroringAsserts(List<Function<T, Optional<Throwable>>> tests) {
		this.tests = tests;
	}

	@Override
	public List<Throwable> errorsIn(T instance) {
		return tests
				.stream()
				.flatMap(t -> t.apply(instance).map(Stream::of).orElse(Stream.empty()))
				.collect(Collectors.toList());
	}
}
